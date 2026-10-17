//! Control-plane client for the desktop app. Uses the HTTPS-only native adapter so requests run off the
//! UI thread; each call reports back through an mpsc channel as a [`Msg`], and
//! the UI thread repaints when one arrives.

use std::sync::mpsc::Sender;

use serde::Deserialize;
use crate::http;

#[derive(Clone, Debug, Deserialize)]
pub struct Me {
    pub account_number: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Dashboard {
    pub nodes_online: u32,
    pub nodes_total: u32,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct Node {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub capacity_mbps: u32,
    #[serde(default)]
    pub status: String,
}

impl Node {
    pub fn online(&self) -> bool {
        matches!(self.status.as_str(), "active" | "listed" | "online")
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Denom {
    pub label: String,
    pub duration_days: u32,
    #[serde(default)]
    pub price_xmr: String,
    #[serde(default)]
    pub price_btc: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DenomResp {
    #[serde(default)]
    pub rails: Vec<String>,
    #[serde(default)]
    pub denominations: Vec<Denom>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Grant {
    pub grant: String,
    pub plan: String,
    pub expires_at: String,
}

/// Results delivered from background requests to the UI thread.
pub enum Msg {
    Registered(String), // account number
    LoggedIn(String),   // token
    Me(Me),
    Dash(Dashboard),
    Nodes(Vec<Node>),
    Denoms(DenomResp),
    Granted(Grant),
    Deleted,
    Err(String),
}

#[derive(Deserialize)]
struct ApiErr {
    #[serde(default)]
    error: String,
}

fn err_from(status: u16, body: &str) -> String {
    serde_json::from_str::<ApiErr>(body)
        .ok()
        .filter(|e| !e.error.is_empty())
        .map(|e| e.error)
        .unwrap_or_else(|| format!("request failed ({status})"))
}

/// Fire a request; on completion, decode `T` and map it to a [`Msg`] via `ok`,
/// or send [`Msg::Err`]. Repaints the UI when done.
fn send<T: for<'de> Deserialize<'de>>(
    ctx: egui::Context,
    tx: Sender<Msg>,
    req: http::Request,
    ok: impl FnOnce(T) -> Msg + Send + 'static,
) {
    http::fetch(req, move |res| {
        let msg = match res {
            Ok(r) => {
                let body = r.text().unwrap_or_default();
                if (200..300).contains(&r.status) {
                    match serde_json::from_str::<T>(&body) {
                        Ok(v) => ok(v),
                        Err(e) => Msg::Err(format!("bad response: {e}")),
                    }
                } else {
                    Msg::Err(err_from(r.status, &body))
                }
            }
            Err(e) => Msg::Err(e),
        };
        let _ = tx.send(msg);
        ctx.request_repaint();
    });
}

fn post_json(url: String, body: serde_json::Value, token: Option<&str>) -> http::Request {
    let mut req = http::Request::post(url, body.to_string().into_bytes());
    req.headers.insert("Content-Type", "application/json");
    if let Some(t) = token {
        req.headers.insert("Authorization", format!("Bearer {t}"));
    }
    req
}

fn get(url: String, token: Option<&str>) -> http::Request {
    let mut req = http::Request::get(url);
    if let Some(t) = token {
        req.headers.insert("Authorization", format!("Bearer {t}"));
    }
    req
}

/// The control-plane API, bound to a base URL.
#[derive(Clone)]
pub struct Api {
    pub base: String,
    pub ctx: egui::Context,
    pub tx: Sender<Msg>,
}

impl Api {
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base.trim_end_matches('/'), path)
    }

    pub fn register(&self, password: &str) {
        let req = post_json(self.url("/api/auth/register"), serde_json::json!({"password": password}), None);
        send(self.ctx.clone(), self.tx.clone(), req, |r: Me| Msg::Registered(r.account_number));
    }

    pub fn login(&self, account: &str, password: &str) {
        #[derive(Deserialize)]
        struct Tok { token: String }
        let body = serde_json::json!({"account_number": account, "password": password});
        let req = post_json(self.url("/api/auth/login"), body, None);
        send(self.ctx.clone(), self.tx.clone(), req, |r: Tok| Msg::LoggedIn(r.token));
    }

    pub fn me(&self, token: &str) {
        send(self.ctx.clone(), self.tx.clone(), get(self.url("/api/me"), Some(token)), Msg::Me);
    }

    pub fn dashboard(&self, token: &str) {
        send(self.ctx.clone(), self.tx.clone(), get(self.url("/api/dashboard"), Some(token)), Msg::Dash);
    }

    pub fn nodes(&self, token: &str) {
        send(self.ctx.clone(), self.tx.clone(), get(self.url("/api/nodes"), Some(token)), Msg::Nodes);
    }

    pub fn denominations(&self) {
        send(self.ctx.clone(), self.tx.clone(), get(self.url("/api/pay/denominations"), None), Msg::Denoms);
    }

    pub fn claim_code(&self, code: &str) {
        let req = post_json(self.url("/api/pay/claim-code"), serde_json::json!({"code": code}), None);
        send(self.ctx.clone(), self.tx.clone(), req, Msg::Granted);
    }

    pub fn delete_account(&self, token: &str, password: &str) {
        let mut req = post_json(self.url("/api/me"), serde_json::json!({"password": password}), Some(token));
        req.method = "DELETE".into();
        // DELETE returns an empty 2xx body, so check the status directly rather
        // than decoding JSON.
        let (ctx, tx) = (self.ctx.clone(), self.tx.clone());
        http::fetch(req, move |res| {
            let msg = match res {
                Ok(r) if (200..300).contains(&r.status) => Msg::Deleted,
                Ok(r) => Msg::Err(err_from(r.status, &r.text().unwrap_or_default())),
                Err(e) => Msg::Err(e),
            };
            let _ = tx.send(msg);
            ctx.request_repaint();
        });
    }
}
