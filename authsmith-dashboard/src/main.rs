//! AuthSmith Dashboard — native + WASM admin UI built with egui/eframe.
//!
//! Run with:
//!   cargo run -p authsmith-dashboard
//!
//! For a WASM build, use `trunk` with an `index.html` entry point that calls
//! `eframe::WebRunner` (eframe's standard WASM bootstrap).

mod app;
mod client;
mod types;
mod views;

fn main() -> eframe::Result {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("AuthSmith Dashboard")
            .with_inner_size([1_100.0, 700.0])
            .with_min_inner_size([800.0, 500.0]),
        ..Default::default()
    };

    eframe::run_native(
        "AuthSmith Dashboard",
        native_options,
        Box::new(|cc| Ok(Box::new(app::DashboardApp::new(cc)))),
    )
}
