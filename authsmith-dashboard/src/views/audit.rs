//! Audit-log panel — view chronological auth events.

use egui::{Color32, RichText, Ui};

use crate::app::{DashboardApp, LoadState};
use crate::views::format_timestamp;

/// Color-code well-known event names to make scanning easier.
fn event_color(event: &str) -> Option<Color32> {
    if event.contains("fail") || event.contains("error") || event.contains("ban") {
        Some(Color32::RED)
    } else if event.contains("logout") || event.contains("revoke") {
        Some(Color32::YELLOW)
    } else if event.contains("login") || event.contains("register") {
        Some(Color32::from_rgb(80, 200, 120))
    } else {
        None
    }
}

pub fn show(app: &mut DashboardApp, ui: &mut Ui) {
    let mut do_refresh = false;

    // ── Header ────────────────────────────────────────────────────────────────
    ui.horizontal(|ui| {
        ui.heading("Audit Log");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("⟳  Refresh").clicked() {
                do_refresh = true;
            }
        });
    });
    ui.separator();

    // ── Data table ────────────────────────────────────────────────────────────
    match &app.audit {
        LoadState::Idle => {
            ui.label("No data — click Refresh.");
        }

        LoadState::Loading => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Loading audit events…");
            });
        }

        LoadState::Error(e) => {
            ui.colored_label(Color32::RED, format!("Error: {e}"));
            if ui.small_button("Retry").clicked() {
                do_refresh = true;
            }
        }

        LoadState::Loaded(events) => {
            ui.label(format!("{} event(s) (server-limited)", events.len()));
            ui.separator();

            egui::ScrollArea::vertical().show(ui, |ui| {
                egui::Grid::new("audit_table")
                    .num_columns(4)
                    .striped(true)
                    .spacing([16.0, 4.0])
                    .show(ui, |ui| {
                        // Header
                        ui.label(RichText::new("Event").strong());
                        ui.label(RichText::new("User ID").strong());
                        ui.label(RichText::new("IP").strong());
                        ui.label(RichText::new("Time").strong());
                        ui.end_row();

                        for event in events {
                            let label = if let Some(color) = event_color(&event.event) {
                                RichText::new(&event.event).color(color)
                            } else {
                                RichText::new(&event.event)
                            };

                            let resp = ui.label(label);
                            // Show JSON metadata in tooltip when available
                            if let Some(meta) = &event.metadata {
                                resp.on_hover_text(meta.to_string());
                            }

                            let short_uid = event
                                .user_id
                                .as_deref()
                                .map(|id| &id[..id.len().min(8)])
                                .unwrap_or("—");
                            ui.label(short_uid)
                                .on_hover_text(event.user_id.as_deref().unwrap_or("—"));

                            ui.label(event.ip.as_deref().unwrap_or("—"));
                            ui.label(format_timestamp(event.timestamp));
                            ui.end_row();
                        }
                    });
            });
        }
    }

    // ── Process deferred actions ──────────────────────────────────────────────
    if do_refresh {
        app.load_audit();
    }
}
