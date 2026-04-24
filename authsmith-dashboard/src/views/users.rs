//! Users panel — list, search, ban, and delete users.

use egui::{Color32, RichText, Ui};

use crate::app::{DashboardApp, LoadState};

pub fn show(app: &mut DashboardApp, ui: &mut Ui) {
    // Collect deferred actions to avoid borrow conflicts with `app.users`.
    let mut do_refresh = false;
    let mut ban_id: Option<String> = None;
    let mut delete_id: Option<String> = None;

    // ── Header ────────────────────────────────────────────────────────────────
    ui.horizontal(|ui| {
        ui.heading("Users");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("⟳  Refresh").clicked() {
                do_refresh = true;
            }
        });
    });
    ui.separator();

    // ── Search bar ────────────────────────────────────────────────────────────
    ui.horizontal(|ui| {
        ui.label("🔍");
        ui.text_edit_singleline(&mut app.user_search);
        if !app.user_search.is_empty() && ui.small_button("✕").clicked() {
            app.user_search.clear();
        }
    });
    ui.add_space(6.0);

    // Snapshot the search string so we don't hold a borrow on app inside the match.
    let search = app.user_search.to_lowercase();

    // ── Data table ────────────────────────────────────────────────────────────
    match &app.users {
        LoadState::Idle => {
            ui.label("No data — click Refresh.");
        }

        LoadState::Loading => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Loading users…");
            });
        }

        LoadState::Error(e) => {
            ui.colored_label(Color32::RED, format!("Error: {e}"));
            if ui.small_button("Retry").clicked() {
                do_refresh = true;
            }
        }

        LoadState::Loaded(users) => {
            let filtered: Vec<_> = users
                .iter()
                .filter(|u| {
                    if search.is_empty() {
                        return true;
                    }
                    u.id.to_lowercase().contains(&search)
                        || u.email
                            .as_deref()
                            .unwrap_or("")
                            .to_lowercase()
                            .contains(&search)
                        || u.roles.iter().any(|r| r.to_lowercase().contains(&search))
                })
                .collect();

            ui.label(format!(
                "{} user(s){}",
                filtered.len(),
                if filtered.len() != users.len() {
                    format!(" (of {})", users.len())
                } else {
                    String::new()
                }
            ));
            ui.separator();

            egui::ScrollArea::vertical().show(ui, |ui| {
                egui::Grid::new("users_table")
                    .num_columns(5)
                    .striped(true)
                    .spacing([16.0, 4.0])
                    .min_col_width(60.0)
                    .show(ui, |ui| {
                        // Header row
                        ui.label(RichText::new("ID").strong());
                        ui.label(RichText::new("Email").strong());
                        ui.label(RichText::new("Roles").strong());
                        ui.label(RichText::new("Status").strong());
                        ui.label(RichText::new("Actions").strong());
                        ui.end_row();

                        for user in &filtered {
                            // Truncate long IDs for display
                            let short_id = &user.id[..user.id.len().min(8)];
                            ui.label(short_id)
                                .on_hover_text(user.id.as_str());

                            ui.label(user.email.as_deref().unwrap_or("—"));
                            ui.label(if user.roles.is_empty() {
                                "—".to_owned()
                            } else {
                                user.roles.join(", ")
                            });

                            if user.banned {
                                ui.colored_label(Color32::RED, "Banned");
                            } else {
                                ui.colored_label(Color32::from_rgb(80, 200, 120), "Active");
                            }

                            ui.horizontal(|ui| {
                                if !user.banned
                                    && ui
                                        .add(egui::Button::new("Ban").small())
                                        .on_hover_text("Prevent this user from logging in")
                                        .clicked()
                                {
                                    ban_id = Some(user.id.clone());
                                }
                                if ui
                                    .add(
                                        egui::Button::new(
                                            RichText::new("Delete").color(Color32::RED),
                                        )
                                        .small(),
                                    )
                                    .on_hover_text("Permanently delete this user and all their sessions")
                                    .clicked()
                                {
                                    delete_id = Some(user.id.clone());
                                }
                            });

                            ui.end_row();
                        }
                    });
            });
        }
    }

    // ── Process deferred actions (borrows on `app.users` released above) ──────
    if do_refresh {
        app.load_users();
    }
    if let Some(id) = ban_id {
        app.ban_user(id);
    }
    if let Some(id) = delete_id {
        app.delete_user(id);
    }
}
