//! The SHAIP VPN desktop app: a glass console over the real control plane, with a
//! Connect control that drives the local tunnel engine.

use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

use egui::{Align, Color32, Layout, Rounding, RichText, Vec2};

use crate::api::{Api, Dashboard, DenomResp, Grant, Me, Msg, Node};
use crate::theme::{self, HAIRLINE, INK, INK2, INK3, OK, SIGNAL, STEEL, THREAT};

#[derive(PartialEq, Clone, Copy)]
enum Screen {
    Dashboard,
    Servers,
    Buy,
}

#[derive(PartialEq, Clone, Copy)]
enum Tunnel {
    Off,
    Connecting,
    On,
}

pub struct DesktopApp {
    ctx: egui::Context,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    api_base: String,

    token: Option<String>,
    // login
    register: bool,
    account: String,
    password: String,
    created: Option<String>,
    noted: bool,
    err: Option<String>,
    busy: bool,
    // signed-in
    screen: Screen,
    loaded: bool,
    me: Option<Me>,
    dash: Option<Dashboard>,
    nodes: Option<Vec<Node>>,
    denoms: Option<DenomResp>,
    code: String,
    grant: Option<Grant>,
    code_err: Option<String>,
    show_delete: bool,
    delete_pw: String,
    tunnel: Tunnel,
    tunnel_note: Option<String>,
    last_status: Option<Instant>,
}

impl DesktopApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::install(&cc.egui_ctx);
        let (tx, rx) = channel();
        let api_base = std::env::var("SHAIP_API")
            .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());

        // Offline preview mode (SHAIP_DEMO=1): seed sample infrastructure data so
        // the signed-in screens render without a backend. Sample node names and a
        // placeholder account number only — never customer data. Used for
        // screenshots and demos. SHAIP_SCREEN picks the initial tab.
        let demo = std::env::var("SHAIP_DEMO").is_ok();
        let (token, me, dash, nodes, denoms) = if demo {
            (
                Some("demo".to_string()),
                Some(Me { account_number: "1234567890123456".into() }),
                Some(Dashboard { nodes_online: 2, nodes_total: 3 }),
                Some(demo_nodes()),
                Some(demo_denoms()),
            )
        } else {
            (None, None, None, None, None)
        };
        let screen = match std::env::var("SHAIP_SCREEN").as_deref() {
            Ok("servers") => Screen::Servers,
            Ok("buy") => Screen::Buy,
            _ => Screen::Dashboard,
        };
        let grant = if demo && screen == Screen::Buy {
            Some(Grant { grant: "eyJzdWQiOiI…sample-access-grant…".into(), plan: "pro".into(), expires_at: "2027-10-17".into() })
        } else {
            None
        };

        Self {
            ctx: cc.egui_ctx.clone(),
            tx,
            rx,
            api_base,
            token,
            register: false,
            account: String::new(),
            password: String::new(),
            created: None,
            noted: false,
            err: None,
            busy: false,
            screen,
            loaded: false,
            me,
            dash,
            nodes,
            denoms,
            code: String::new(),
            grant,
            code_err: None,
            show_delete: false,
            delete_pw: String::new(),
            tunnel: Tunnel::Off,
            tunnel_note: None,
            last_status: None,
        }
    }

    fn api(&self) -> Api {
        Api { base: self.api_base.clone(), ctx: self.ctx.clone(), tx: self.tx.clone() }
    }

    fn pump(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            self.busy = false;
            match msg {
                Msg::Registered(acct) => {
                    self.created = Some(acct);
                    self.err = None;
                }
                Msg::LoggedIn(token) => {
                    let api = self.api();
                    api.me(&token);
                    api.dashboard(&token);
                    api.nodes(&token);
                    api.denominations();
                    self.token = Some(token);
                    self.loaded = true;
                    self.err = None;
                }
                Msg::Me(me) => self.me = Some(me),
                Msg::Dash(d) => self.dash = Some(d),
                Msg::Nodes(n) => self.nodes = Some(n),
                Msg::Denoms(d) => self.denoms = Some(d),
                Msg::Granted(g) => {
                    self.grant = Some(g);
                    self.code_err = None;
                }
                Msg::Deleted => self.sign_out(),
                Msg::Err(e) => {
                    // A code-claim error belongs by the code box; everything else
                    // is the general error line.
                    if self.grant.is_none() && !self.code.is_empty() {
                        self.code_err = Some(e);
                    } else {
                        self.err = Some(e);
                    }
                }
            }
        }
    }

    fn sign_out(&mut self) {
        self.token = None;
        self.me = None;
        self.dash = None;
        self.nodes = None;
        self.created = None;
        self.account.clear();
        self.password.clear();
        self.loaded = false;
        self.tunnel = Tunnel::Off;
    }
}

fn group_account(n: &str) -> String {
    let digits: String = n.chars().filter(|c| c.is_ascii_digit()).collect();
    digits
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(" ")
}

fn eyebrow(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text.to_uppercase()).color(INK3).font(theme::mono(11.0)));
}

fn primary_button(ui: &mut egui::Ui, text: &str, enabled: bool) -> bool {
    let fill = if enabled { Color32::WHITE } else { Color32::from_white_alpha(90) };
    let btn = egui::Button::new(RichText::new(text).color(theme::BG2).strong())
        .fill(fill)
        .rounding(Rounding::same(999.0))
        .min_size(Vec2::new(0.0, 40.0));
    ui.add_enabled(enabled, btn).clicked()
}

fn glass_button(ui: &mut egui::Ui, text: &str, enabled: bool) -> bool {
    let btn = egui::Button::new(RichText::new(text).color(INK))
        .fill(Color32::from_white_alpha(20))
        .stroke(egui::Stroke::new(1.0_f32, HAIRLINE))
        .rounding(Rounding::same(999.0))
        .min_size(Vec2::new(0.0, 38.0));
    ui.add_enabled(enabled, btn).clicked()
}

fn field(ui: &mut egui::Ui, value: &mut String, hint: &str, password: bool, mono: bool) -> egui::Response {
    let mut te = egui::TextEdit::singleline(value)
        .hint_text(hint)
        .desired_width(f32::INFINITY)
        .margin(egui::Margin::symmetric(10.0, 8.0))
        .password(password);
    if mono {
        te = te.font(theme::mono(14.0));
    }
    ui.add(te)
}

fn status_pill(ui: &mut egui::Ui, label: &str, tint: Color32) {
    egui::Frame::none()
        .fill(tint.linear_multiply(0.14))
        .stroke(egui::Stroke::new(1.0_f32, tint.linear_multiply(0.5)))
        .rounding(Rounding::same(10.0))
        .inner_margin(egui::Margin::symmetric(8.0, 3.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("●").color(tint).size(8.0));
                ui.label(RichText::new(label.to_uppercase()).color(tint).font(theme::mono(10.0)));
            });
        });
}

impl eframe::App for DesktopApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.pump();
        // Keep the tunnel indicator truthful: poll the engine's real status, and
        // keep repainting so it updates even without user input.
        self.refresh_status(false);
        ctx.request_repaint_after(Duration::from_secs(2));

        egui::CentralPanel::default()
            .frame(egui::Frame::none())
            .show(ctx, |ui| {
                theme::paint_gradient(ui);
                if self.token.is_none() {
                    self.login_screen(ui);
                } else {
                    self.signed_in(ui);
                }
            });
    }
}

impl DesktopApp {
    fn login_screen(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(ui.available_height() * 0.18);
            ui.allocate_ui_with_layout(
                Vec2::new(380.0, 0.0),
                Layout::top_down(Align::Min),
                |ui| {
                    theme::glass().show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("●").color(SIGNAL).size(9.0));
                            eyebrow(ui, "SHAIP VPN · Post-quantum VPN");
                        });
                        ui.label(RichText::new("SHAIP VPN").color(SIGNAL).font(theme::mono(26.0)).strong());
                        ui.add_space(4.0);

                        if let Some(acct) = self.created.clone() {
                            ui.label(RichText::new("Your account number is your login:").color(INK2));
                            ui.label(RichText::new(group_account(&acct)).color(INK).font(theme::mono(20.0)));
                            ui.label(RichText::new(
                                "Write it down and keep it with your password. We don't know who \
                                 you are, so we can't recover it. It is shown only now.",
                            ).color(INK2).size(12.0));
                            ui.checkbox(&mut self.noted, RichText::new("I've written it down").color(INK2));
                            if let Some(e) = &self.err {
                                ui.label(RichText::new(e).color(THREAT).size(12.0));
                            }
                            if primary_button(ui, "Continue", self.noted && !self.busy) {
                                self.busy = true;
                                let pw = self.password.clone();
                                self.api().login(&acct, &pw);
                            }
                        } else {
                            ui.label(
                                RichText::new(if self.register {
                                    "Create an account. No email or name: you get a random account number."
                                } else {
                                    "Sign in with your account number"
                                })
                                .color(INK2),
                            );
                            if !self.register {
                                field(ui, &mut self.account, "1234 5678 9012 3456", false, true);
                            }
                            field(ui, &mut self.password, "password (min 8 chars)", true, false);
                            if let Some(e) = &self.err {
                                ui.label(RichText::new(e).color(THREAT).size(12.0));
                            }
                            let label = if self.register { "Create account" } else { "Sign in" };
                            if primary_button(ui, label, !self.busy) {
                                self.busy = true;
                                self.err = None;
                                if self.register {
                                    let pw = self.password.clone();
                                    self.api().register(&pw);
                                } else {
                                    let (a, p) = (self.account.clone(), self.password.clone());
                                    self.api().login(&a, &p);
                                }
                            }
                            let toggle = if self.register {
                                "Have an account number? Sign in"
                            } else {
                                "Need an account? Create one"
                            };
                            if ui.add(egui::Button::new(RichText::new(toggle).color(INK2)).frame(false)).clicked() {
                                self.register = !self.register;
                                self.err = None;
                            }
                        }
                    });
                },
            );
        });
    }

    fn signed_in(&mut self, ui: &mut egui::Ui) {
        // Top bar: brand + tabs + sign out.
        egui::Frame::none()
            .fill(Color32::from_white_alpha(18))
            .inner_margin(egui::Margin::symmetric(16.0, 10.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("SHAIP VPN").color(SIGNAL).font(theme::mono(18.0)).strong());
                    ui.add_space(16.0);
                    for (s, label) in [
                        (Screen::Dashboard, "Dashboard"),
                        (Screen::Servers, "Servers"),
                        (Screen::Buy, "Buy access"),
                    ] {
                        let active = self.screen == s;
                        let color = if active { INK } else { INK3 };
                        if ui.add(egui::Button::new(RichText::new(label).color(color)).frame(false)).clicked() {
                            self.screen = s;
                        }
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.add(egui::Button::new(RichText::new("Sign out").color(INK2)).frame(false)).clicked() {
                            self.sign_out();
                        }
                    });
                });
            });

        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.add_space(16.0);
            egui::Frame::none().inner_margin(egui::Margin::symmetric(18.0, 4.0)).show(ui, |ui| {
                match self.screen {
                    Screen::Dashboard => self.dashboard_screen(ui),
                    Screen::Servers => self.servers_screen(ui),
                    Screen::Buy => self.buy_screen(ui),
                }
            });
            ui.add_space(24.0);
        });
    }

    fn dashboard_screen(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("Dashboard").color(INK).font(theme::sans(28.0)).strong());
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            if let Some(me) = &self.me {
                stat_card(ui, "Your account number", &group_account(&me.account_number), SIGNAL, true);
            }
            if let Some(d) = &self.dash {
                stat_card(ui, "Servers online", &format!("{} of {}", d.nodes_online, d.nodes_total), INK, false);
            }
        });
        ui.add_space(8.0);
        theme::glass().show(ui, |ui| {
            eyebrow(ui, "Tunnel");
            let (label, tint) = match self.tunnel {
                Tunnel::On => ("Connected", OK),
                Tunnel::Connecting => ("Connecting", theme::INK2),
                Tunnel::Off => ("Disconnected", STEEL),
            };
            status_pill(ui, label, tint);
            ui.add_space(6.0);
            let clicked = match self.tunnel {
                Tunnel::Off => primary_button(ui, "Connect", true),
                _ => glass_button(ui, "Disconnect", true),
            };
            if clicked {
                self.toggle_tunnel();
            }
            if let Some(n) = &self.tunnel_note {
                ui.label(RichText::new(n).color(INK3).size(12.0));
            }
            ui.label(RichText::new(
                "The desktop app drives the local tunnel engine (the shaip client, shared with \
                 the CLI). The post-quantum handshake (ML-KEM-768 + ML-DSA-65) and the encrypted \
                 tunnel run in that engine; it needs admin/root to open the TUN device.",
            ).color(INK3).size(12.0));
        });
        ui.add_space(8.0);
        ui.label(RichText::new(
            "This page shows the network, never your activity: the control plane keeps no record \
             of your connections, traffic or the sites you visit.",
        ).color(INK2).size(13.0));
        ui.add_space(8.0);
        if !self.show_delete {
            if ui.add(egui::Button::new(RichText::new("Delete account…").color(THREAT)).frame(false)).clicked() {
                self.show_delete = true;
            }
        } else {
            theme::glass().show(ui, |ui| {
                ui.label(RichText::new("Delete this account").color(THREAT).strong());
                ui.label(RichText::new(
                    "Everything stored about it is erased: its devices, API keys and security log. \
                     This can't be undone.",
                ).color(INK2).size(13.0));
                field(ui, &mut self.delete_pw, "your password", true, false);
                ui.horizontal(|ui| {
                    if primary_button(ui, "Delete forever", !self.busy) {
                        self.busy = true;
                        if let Some(t) = self.token.clone() {
                            let pw = self.delete_pw.clone();
                            self.api().delete_account(&t, &pw);
                        }
                    }
                    if ui.add(egui::Button::new(RichText::new("Cancel").color(INK2)).frame(false)).clicked() {
                        self.show_delete = false;
                    }
                });
            });
        }
    }

    fn servers_screen(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Servers").color(INK).font(theme::sans(28.0)).strong());
            if let Some(nodes) = &self.nodes {
                let online = nodes.iter().filter(|n| n.online()).count();
                let regions = nodes.iter().filter(|n| !n.region.is_empty()).map(|n| &n.region).collect::<std::collections::HashSet<_>>().len();
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    eyebrow(ui, &format!("{} nodes · {} online · {} region", nodes.len(), online, regions));
                });
            }
        });
        ui.add_space(8.0);
        match &self.nodes {
            None => { ui.label(RichText::new("Loading…").color(INK3)); }
            Some(nodes) if nodes.is_empty() => {
                theme::tile().show(ui, |ui| {
                    ui.label(RichText::new("No servers are listed yet.").color(INK2));
                });
            }
            Some(nodes) => {
                let nodes = nodes.clone();
                theme::tile().show(ui, |ui| {
                    egui::Grid::new("nodes").num_columns(4).striped(true).spacing([16.0, 10.0]).show(ui, |ui| {
                        for h in ["SERVER", "ROLE", "CAPACITY", "STATUS"] {
                            ui.label(RichText::new(h).color(INK3).font(theme::mono(11.0)));
                        }
                        ui.end_row();
                        for n in &nodes {
                            ui.vertical(|ui| {
                                ui.label(RichText::new(if n.name.is_empty() { &n.id } else { &n.name }).color(INK));
                                if !n.address.is_empty() {
                                    ui.label(RichText::new(&n.address).color(INK3).font(theme::mono(11.0)));
                                }
                            });
                            ui.label(RichText::new(role_label(&n.role)).color(INK2));
                            ui.label(RichText::new(if n.capacity_mbps > 0 { format!("{} Mbps", n.capacity_mbps) } else { "—".into() }).color(INK2).font(theme::mono(13.0)));
                            if n.online() {
                                status_pill(ui, "online", OK);
                            } else {
                                status_pill(ui, "offline", STEEL);
                            }
                            ui.end_row();
                        }
                    });
                });
            }
        }
        ui.add_space(8.0);
        ui.label(RichText::new(
            "The directory is signed by the control plane and verified by the client before it \
             trusts a server. The tunnel connects to one server at a time — there is no mix \
             routing yet.",
        ).color(INK2).size(13.0));
    }

    fn buy_screen(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("SHAIP VPN — Private access").color(SIGNAL).font(theme::mono(22.0)).strong());
        ui.label(RichText::new(
            "Pay with Monero or Bitcoin. Get blind-signed access tokens: the token you redeem \
             carries nothing that links it to your payment (RFC 9474 blind signatures).",
        ).color(INK2).size(14.0));
        ui.add_space(8.0);
        if let Some(d) = self.denoms.clone() {
            let mut title = "Plans".to_string();
            if !d.rails.is_empty() {
                title = format!("Plans  ·  paid in {}", d.rails.join(" / "));
            }
            ui.label(RichText::new(title).color(SIGNAL).font(theme::sans(18.0)).strong());
            theme::tile().show(ui, |ui| {
                egui::Grid::new("plans").num_columns(4).striped(true).spacing([16.0, 10.0]).show(ui, |ui| {
                    for h in ["PLAN", "DURATION", "MONERO", "BITCOIN"] {
                        ui.label(RichText::new(h).color(INK3).font(theme::mono(11.0)));
                    }
                    ui.end_row();
                    for p in &d.denominations {
                        ui.label(RichText::new(&p.label).color(INK));
                        ui.label(RichText::new(format!("{} days", p.duration_days)).color(INK2));
                        ui.label(RichText::new(format!("{} XMR", p.price_xmr)).color(INK2).font(theme::mono(13.0)));
                        ui.label(RichText::new(format!("{} BTC", p.price_btc)).color(INK2).font(theme::mono(13.0)));
                        ui.end_row();
                    }
                });
            });
        }
        ui.add_space(10.0);
        ui.label(RichText::new("Have a code?").color(SIGNAL).font(theme::sans(18.0)).strong());
        ui.label(RichText::new(
            "A discount, promo, or test code grants access without a payment. Claiming a code is \
             identity-free: no account, no card, and it records only that one use was spent.",
        ).color(INK2).size(13.0));
        ui.horizontal(|ui| {
            field(ui, &mut self.code, "SHAIP-XXXX-XXXX-XXXX", false, true);
            if glass_button(ui, "Redeem", !self.code.trim().is_empty() && !self.busy) {
                self.busy = true;
                self.grant = None;
                self.code_err = None;
                let c = self.code.trim().to_string();
                self.api().claim_code(&c);
            }
        });
        if let Some(e) = &self.code_err {
            ui.label(RichText::new(e).color(THREAT).size(13.0));
        }
        if let Some(g) = self.grant.clone() {
            theme::glass().show(ui, |ui| {
                ui.label(RichText::new(format!("Access granted — plan: {}", g.plan)).color(OK).strong());
                ui.label(RichText::new(format!("Valid until {}.", &g.expires_at.chars().take(10).collect::<String>())).color(OK).size(13.0));
                ui.label(RichText::new("Your access grant (paste into the app / CLI):").color(INK2).size(13.0));
                ui.label(RichText::new(&g.grant).color(INK3).font(theme::mono(11.0)));
            });
        }
    }

    fn toggle_tunnel(&mut self) {
        match self.tunnel {
            Tunnel::Off => {
                // Starting the tunnel needs a saved server config and admin rights.
                // We NEVER show "Connected" from anything less than the engine's own
                // status — a running binary is not a live tunnel.
                let cfg = config_path();
                if !cfg.exists() {
                    self.tunnel = Tunnel::Off;
                    self.tunnel_note = Some(format!(
                        "No server configured ({}). Add a client config, then connect — \
                         the app stays DISCONNECTED until the engine confirms a live tunnel.",
                        cfg.display()
                    ));
                    return;
                }
                // Launch the real engine (shaip run). It needs CAP_NET_ADMIN; if it
                // can't establish, the status poll below keeps the state at
                // Disconnected rather than claiming protection.
                self.tunnel = Tunnel::Connecting;
                self.tunnel_note = Some("Starting the tunnel…".into());
                let spawned = std::process::Command::new("shaip")
                    .arg("run").arg("--config").arg(&cfg).arg("--kill-switch")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn();
                if spawned.is_err() {
                    self.tunnel = Tunnel::Off;
                    self.tunnel_note = Some("Tunnel engine (shaip) is not installed on this machine.".into());
                }
                self.last_status = None; // force an immediate status refresh
            }
            _ => {
                let _ = std::process::Command::new("shaip").arg("disconnect").output();
                self.refresh_status(true);
            }
        }
    }

    /// Set the tunnel state from the engine's own `shaip status`. This is the only
    /// thing allowed to show "Connected": a live tunnel with an assigned address,
    /// reported by the engine — never a mere process check.
    fn refresh_status(&mut self, force: bool) {
        if !force {
            if let Some(t) = self.last_status {
                if t.elapsed() < Duration::from_secs(2) {
                    return;
                }
            }
        }
        self.last_status = Some(Instant::now());
        let (t, note) = shaip_status();
        // Keep a transient "Connecting…" note while a just-launched engine has not
        // yet written a status; don't override it with a bare "disconnected".
        if self.tunnel == Tunnel::Connecting && t == Tunnel::Off && note.is_none() {
            return;
        }
        self.tunnel = t;
        if note.is_some() || t != Tunnel::Connecting {
            self.tunnel_note = note;
        }
    }
}

/// Where a saved client config lives. `shaip run` needs one; without it the app
/// cannot (and must not) claim to be connected.
fn config_path() -> std::path::PathBuf {
    if let Some(h) = std::env::var_os("HOME") {
        std::path::PathBuf::from(h).join(".config/shaip/client.toml")
    } else {
        std::path::PathBuf::from("client.toml")
    }
}

/// Read the engine's real state via `shaip status`. Returns On only when the
/// status file reports a running tunnel with an assigned address.
fn shaip_status() -> (Tunnel, Option<String>) {
    let out = match std::process::Command::new("shaip").arg("status").output() {
        Ok(o) => o,
        Err(_) => return (Tunnel::Off, Some("Tunnel engine (shaip) is not installed on this machine.".into())),
    };
    let text = String::from_utf8_lossy(&out.stdout);
    if text.contains("state=NotRunning") || text.trim().is_empty() {
        return (Tunnel::Off, None);
    }
    let addr = text.lines()
        .find_map(|l| l.strip_prefix("tunnel_address="))
        .map(str::trim)
        .unwrap_or("");
    if addr.is_empty() || addr == "-" {
        (Tunnel::Connecting, Some("Establishing the tunnel…".into()))
    } else {
        (Tunnel::On, Some(format!("Protected — tunnel address {addr}")))
    }
}

fn role_label(role: &str) -> String {
    match role {
        "entry" => "Entry",
        "exit" => "Exit",
        "gateway" => "Gateway",
        "mix" => "Mix",
        "" => "—",
        other => other,
    }
    .to_string()
}

fn stat_card(ui: &mut egui::Ui, label: &str, value: &str, value_color: Color32, mono: bool) {
    theme::glass().show(ui, |ui| {
        ui.set_min_width(170.0);
        eyebrow(ui, label);
        let font = if mono { theme::mono(22.0) } else { theme::sans(22.0) };
        ui.label(RichText::new(value).color(value_color).font(font).strong());
    });
}

// --- Offline preview sample data (never customer data) ---

fn demo_nodes() -> Vec<Node> {
    vec![
        Node { id: "tokyo-01".into(), name: "tokyo-01".into(), address: "203.0.113.10:443".into(), role: "mix".into(), region: String::new(), capacity_mbps: 100, status: "active".into() },
        Node { id: "frankfurt-01".into(), name: "frankfurt-01".into(), address: "198.51.100.20:443".into(), role: "mix".into(), region: String::new(), capacity_mbps: 100, status: "listed".into() },
        Node { id: "syd-edge-01".into(), name: "syd-edge-01".into(), address: "vpn-syd.example.net:443".into(), role: "entry".into(), region: "AU".into(), capacity_mbps: 1000, status: "offline".into() },
    ]
}

fn demo_denoms() -> DenomResp {
    use crate::api::Denom;
    DenomResp {
        rails: vec!["xmr".into(), "btc".into()],
        denominations: vec![
            Denom { label: "1 day".into(), duration_days: 1, price_xmr: "0.01".into(), price_btc: "0.0002".into() },
            Denom { label: "1 week".into(), duration_days: 7, price_xmr: "0.05".into(), price_btc: "0.00090909".into() },
            Denom { label: "1 month".into(), duration_days: 30, price_xmr: "0.125".into(), price_btc: "0.00222222".into() },
            Denom { label: "3 months".into(), duration_days: 90, price_xmr: "0.25".into(), price_btc: "0.00454545".into() },
        ],
    }
}
