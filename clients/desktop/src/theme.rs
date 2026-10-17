//! The shared SHAIP glass look, expressed in egui: deep-graphite gradient,
//! translucent rounded "glass" panels, cyan signal accent, monospace labels.
//! Same tokens as the web UI, iOS and Android (clients/ios/design/HANDOFF.md).

use egui::{Color32, FontFamily, FontId, Frame, Margin, Rounding, Stroke};

pub const BG0: Color32 = Color32::from_rgb(0x0B, 0x10, 0x20);
pub const BG2: Color32 = Color32::from_rgb(0x02, 0x03, 0x06);
pub const INK: Color32 = Color32::from_rgb(0xF5, 0xF7, 0xFC);
pub const INK2: Color32 = Color32::from_rgb(0xB6, 0xC0, 0xD4);
pub const INK3: Color32 = Color32::from_rgb(0x8A, 0x9B, 0xB8);
pub const SIGNAL: Color32 = Color32::from_rgb(0x5C, 0xF2, 0xFF);
pub const STEEL: Color32 = Color32::from_rgb(0x8A, 0x9B, 0xB8);
pub const OK: Color32 = Color32::from_rgb(0x62, 0xF5, 0xA8);
pub const THREAT: Color32 = Color32::from_rgb(0xFF, 0x5C, 0x7A);
pub const HAIRLINE: Color32 = Color32::from_rgba_premultiplied(38, 38, 38, 38);

/// Apply the dark glass visuals to the whole app.
pub fn install(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.panel_fill = BG2;
    v.window_fill = BG2;
    v.extreme_bg_color = Color32::from_white_alpha(13); // text field fill
    v.override_text_color = Some(INK);
    v.hyperlink_color = SIGNAL;
    v.selection.bg_fill = SIGNAL.linear_multiply(0.35);
    v.selection.stroke = Stroke::new(1.0_f32, SIGNAL);

    let r = Rounding::same(12.0);
    for w in [
        &mut v.widgets.inactive,
        &mut v.widgets.hovered,
        &mut v.widgets.active,
        &mut v.widgets.open,
    ] {
        w.rounding = r;
        w.bg_fill = Color32::from_white_alpha(18);
        w.weak_bg_fill = Color32::from_white_alpha(18);
        w.bg_stroke = Stroke::new(1.0_f32, HAIRLINE);
        w.fg_stroke = Stroke::new(1.0_f32, INK);
    }
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, HAIRLINE);
    ctx.set_visuals(v);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.button_padding = egui::vec2(14.0, 8.0);
    ctx.set_style(style);
}

/// A primary glass card frame.
pub fn glass() -> Frame {
    Frame::none()
        .fill(Color32::from_white_alpha(20))
        .stroke(Stroke::new(1.0_f32, HAIRLINE))
        .rounding(Rounding::same(18.0))
        .inner_margin(Margin::same(18.0))
}

/// A secondary glass tile (lists, tables).
pub fn tile() -> Frame {
    Frame::none()
        .fill(Color32::from_white_alpha(12))
        .stroke(Stroke::new(1.0_f32, Color32::from_white_alpha(26)))
        .rounding(Rounding::same(16.0))
        .inner_margin(Margin::same(6.0))
}

pub fn mono(size: f32) -> FontId {
    FontId::new(size, FontFamily::Monospace)
}

pub fn sans(size: f32) -> FontId {
    FontId::new(size, FontFamily::Proportional)
}

/// Paint the vertical graphite gradient behind the current UI rect.
pub fn paint_gradient(ui: &egui::Ui) {
    use egui::epaint::{Mesh, Vertex, WHITE_UV};
    let rect = ui.max_rect();
    let mut mesh = Mesh::default();
    let (t, b) = (BG0, BG2);
    mesh.vertices.push(Vertex { pos: rect.left_top(), uv: WHITE_UV, color: t });
    mesh.vertices.push(Vertex { pos: rect.right_top(), uv: WHITE_UV, color: t });
    mesh.vertices.push(Vertex { pos: rect.right_bottom(), uv: WHITE_UV, color: b });
    mesh.vertices.push(Vertex { pos: rect.left_bottom(), uv: WHITE_UV, color: b });
    mesh.indices.extend_from_slice(&[0, 1, 2, 0, 2, 3]);
    ui.painter().add(egui::Shape::mesh(mesh));
}
