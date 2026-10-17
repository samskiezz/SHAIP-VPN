// On Windows release builds, don't attach a console window to the GUI app.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod app;
mod theme;

use app::DesktopApp;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([600.0, 820.0])
            .with_min_inner_size([360.0, 560.0])
            .with_title("PQ·ANON"),
        ..Default::default()
    };
    eframe::run_native(
        "PQ·ANON",
        options,
        Box::new(|cc| Ok(Box::new(DesktopApp::new(cc)))),
    )
}
