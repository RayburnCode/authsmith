//! Sessions panel — view active sessions and revoke them.

use egui::{Color32, RichText, Ui};

use crate::app::{DashboardApp, LoadState};
use crate::views::format_timestamp;

pub fn show(app: &mut DashboardApp, ui: &mut Ui) {
    let mut do_refresh = false;
    let mut revoke_token: Option<String> = None;

    // ── Header ────────────────────────────────────────────────────────────────
    ui.horizontal(|ui| {
        ui.heading("Sessions");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("⟳  Refresh").clicked() {
                do_refresh = true;
            }
        });
    });
    ui.separator();

    // ── Data table ────────────────────────────────────────────────────────────
    match &app.sessions {
        LoadState::Idle => {
            ui.label("No data — click Refresh.");
        }

        LoadState::Loading => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Loading sessions…");
            });
        }

        LoadState::Error(e) => {
            ui.colored_label(Color32::RED, format!("Error: {e}"));
            if ui.small_button("Retry").clicked() {
                do_refresh = true;
            }
        }

        LoadState::Loaded(sessions) => {
            ui.label(format!("{} active session(s)", sessions.len()));
            ui.separator();

            egui::ScrollArea::vertical().show(ui, |ui| {
                egui::Grid::new("sessions_table")
                    .num_columns(6)
                    .striped(true)
                    .spacing([16.0, 4.0])
                    .show(ui, |ui| {
                        // Header
                        ui.label(RichText::new("Token").strong());
                        ui.label(RichText::new("User ID").strong());
                        ui.label(RichText::new("Email").strong());
                        ui.label(RichText::new("IP").strong());
                        ui.label(RichText::new("Expires").strong());
                        ui.label(RichText::new("Actions").strong());
                        ui.end_row();

                        for session in sessions {
                            ui.label(format!("{}…", session.token_prefix))
                                .on_hover_text("Token prefix (first 8 chars)");

                            let short_uid = &session.user_id[..session.user_id.len().min(8)];
                            ui.label(short_uid).on_hover_text(session.user_id.as_str());

                            ui.label(session.user_email.as_deref().unwrap_or("—"));
                            ui.label(session.ip.as_deref().unwrap_or("—"));
                            ui.label(format_timestamp(session.expires_at));

                            if ui
                                .add(
                                    egui::Button::new(
                                        RichText::new("Revoke").color(Color32::YELLOW),
                                    )
                                    .small(),
                                )
                                .on_hover_text("Immediately invalidate this session")
                                .clicked()
                            {
                                revoke_token = Some(session.token_prefix.clone());
                            }

                            ui.end_row();
                        }
                    });
            });
        }
    }

    // ── Process deferred actions ──────────────────────────────────────────────
    if do_refresh {
        app.load_sessions();
    }
    if let Some(token) = revoke_token {
        app.revoke_session(token);
    }
}
