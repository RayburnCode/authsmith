//! Core application state and the `eframe::App` implementation.

use std::sync::mpsc;
use std::time::Duration;

use egui::{CentralPanel, Context, TopBottomPanel};

use crate::client::AdminClient;
use crate::types::{AdminSession, AdminUser, AuditEvent};
use crate::views;

// ── Tab ───────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Users,
    Sessions,
    AuditLog,
}

// ── LoadState ─────────────────────────────────────────────────────────────────

/// Tracks the async load lifecycle for any piece of data.
pub enum LoadState<T> {
    /// No load has been initiated yet.
    Idle,
    /// A request is in-flight.
    Loading,
    /// Data arrived successfully.
    Loaded(T),
    /// The request failed; contains the error message.
    Error(String),
}

// ── DashboardApp ──────────────────────────────────────────────────────────────

/// Top-level egui application.
pub struct DashboardApp {
    // -- Connection form -------------------------------------------------------
    pub server_url: String,
    pub admin_token: String,
    pub connected: bool,
    pub connect_error: Option<String>,
    pub client: Option<AdminClient>,

    // -- Navigation -----------------------------------------------------------
    pub active_tab: Tab,

    // -- Remote data ----------------------------------------------------------
    pub users: LoadState<Vec<AdminUser>>,
    pub sessions: LoadState<Vec<AdminSession>>,
    pub audit: LoadState<Vec<AuditEvent>>,

    // -- Async channels -------------------------------------------------------
    //   Each data stream gets its own sender/receiver pair so refreshes and
    //   actions can be pipelined without a mutex.
    rx_users: mpsc::Receiver<Result<Vec<AdminUser>, String>>,
    tx_users: mpsc::SyncSender<Result<Vec<AdminUser>, String>>,

    rx_sessions: mpsc::Receiver<Result<Vec<AdminSession>, String>>,
    tx_sessions: mpsc::SyncSender<Result<Vec<AdminSession>, String>>,

    rx_audit: mpsc::Receiver<Result<Vec<AuditEvent>, String>>,
    tx_audit: mpsc::SyncSender<Result<Vec<AuditEvent>, String>>,

    // -- Tokio runtime --------------------------------------------------------
    rt: tokio::runtime::Runtime,

    // -- Search / filter state ------------------------------------------------
    pub user_search: String,
}

impl DashboardApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let (tx_users, rx_users) = mpsc::sync_channel(8);
        let (tx_sessions, rx_sessions) = mpsc::sync_channel(8);
        let (tx_audit, rx_audit) = mpsc::sync_channel(8);

        Self {
            server_url: "http://localhost:3000".to_owned(),
            admin_token: String::new(),
            connected: false,
            connect_error: None,
            client: None,
            active_tab: Tab::Users,
            users: LoadState::Idle,
            sessions: LoadState::Idle,
            audit: LoadState::Idle,
            rx_users,
            tx_users,
            rx_sessions,
            tx_sessions,
            rx_audit,
            tx_audit,
            rt: tokio::runtime::Runtime::new().expect("tokio runtime"),
            user_search: String::new(),
        }
    }

    // ── Connection ────────────────────────────────────────────────────────────

    pub fn connect(&mut self) {
        let client = AdminClient::new(self.server_url.clone(), self.admin_token.clone());
        self.client = Some(client);
        self.connected = true;
        self.connect_error = None;
        // Eagerly load the first tab
        self.load_users();
    }

    pub fn disconnect(&mut self) {
        self.connected = false;
        self.client = None;
        self.users = LoadState::Idle;
        self.sessions = LoadState::Idle;
        self.audit = LoadState::Idle;
    }

    // ── Data loaders ──────────────────────────────────────────────────────────

    pub fn load_users(&mut self) {
        if let Some(client) = self.client.clone() {
            let tx = self.tx_users.clone();
            self.users = LoadState::Loading;
            self.rt.spawn(async move {
                let _ = tx.send(client.list_users().await);
            });
        }
    }

    pub fn load_sessions(&mut self) {
        if let Some(client) = self.client.clone() {
            let tx = self.tx_sessions.clone();
            self.sessions = LoadState::Loading;
            self.rt.spawn(async move {
                let _ = tx.send(client.list_sessions().await);
            });
        }
    }

    pub fn load_audit(&mut self) {
        if let Some(client) = self.client.clone() {
            let tx = self.tx_audit.clone();
            self.audit = LoadState::Loading;
            self.rt.spawn(async move {
                let _ = tx.send(client.list_audit_events().await);
            });
        }
    }

    // ── Actions (fire-and-reload) ─────────────────────────────────────────────

    pub fn ban_user(&mut self, user_id: String) {
        if let Some(client) = self.client.clone() {
            let tx = self.tx_users.clone();
            self.users = LoadState::Loading;
            self.rt.spawn(async move {
                let _ = client.ban_user(&user_id).await;
                let _ = tx.send(client.list_users().await);
            });
        }
    }

    pub fn delete_user(&mut self, user_id: String) {
        if let Some(client) = self.client.clone() {
            let tx = self.tx_users.clone();
            self.users = LoadState::Loading;
            self.rt.spawn(async move {
                let _ = client.delete_user(&user_id).await;
                let _ = tx.send(client.list_users().await);
            });
        }
    }

    pub fn revoke_session(&mut self, token_prefix: String) {
        if let Some(client) = self.client.clone() {
            let tx = self.tx_sessions.clone();
            self.sessions = LoadState::Loading;
            self.rt.spawn(async move {
                let _ = client.revoke_session(&token_prefix).await;
                let _ = tx.send(client.list_sessions().await);
            });
        }
    }

    // ── Channel polling ───────────────────────────────────────────────────────

    /// Drain all pending channel messages and update load states.
    /// Calls `ctx.request_repaint()` whenever new data arrives.
    fn poll_channels(&mut self, ctx: &Context) {
        if let Ok(result) = self.rx_users.try_recv() {
            self.users = result.map_or_else(LoadState::Error, LoadState::Loaded);
            ctx.request_repaint();
        }
        if let Ok(result) = self.rx_sessions.try_recv() {
            self.sessions = result.map_or_else(LoadState::Error, LoadState::Loaded);
            ctx.request_repaint();
        }
        if let Ok(result) = self.rx_audit.try_recv() {
            self.audit = result.map_or_else(LoadState::Error, LoadState::Loaded);
            ctx.request_repaint();
        }
    }

    fn any_loading(&self) -> bool {
        matches!(self.users, LoadState::Loading)
            || matches!(self.sessions, LoadState::Loading)
            || matches!(self.audit, LoadState::Loading)
    }

    // ── Connect screen ────────────────────────────────────────────────────────

    fn show_connect_screen(&mut self, ctx: &Context) {
        CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(120.0);

                ui.heading("AuthSmith Dashboard");
                ui.add_space(6.0);
                ui.label("Connect to your AuthSmith server to manage users, sessions, and audit logs.");
                ui.add_space(28.0);

                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.set_max_width(420.0);

                    egui::Grid::new("connect_form")
                        .num_columns(2)
                        .spacing([12.0, 10.0])
                        .show(ui, |ui| {
                            ui.label("Server URL");
                            ui.text_edit_singleline(&mut self.server_url);
                            ui.end_row();

                            ui.label("Admin Token");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.admin_token)
                                    .password(true)
                                    .hint_text("authsmith-admin-…"),
                            );
                            ui.end_row();
                        });

                    ui.add_space(10.0);
                    ui.vertical_centered(|ui| {
                        let btn = ui.add_sized([120.0, 28.0], egui::Button::new("Connect"));
                        if btn.clicked() {
                            self.connect();
                        }
                    });

                    if let Some(err) = &self.connect_error.clone() {
                        ui.add_space(6.0);
                        ui.colored_label(egui::Color32::RED, err);
                    }
                });
            });
        });
    }
}

// ── eframe::App ───────────────────────────────────────────────────────────────

impl eframe::App for DashboardApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        self.poll_channels(ctx);

        // Keep the event loop ticking while any async request is in-flight
        if self.any_loading() {
            ctx.request_repaint_after(Duration::from_millis(50));
        }

        if !self.connected {
            self.show_connect_screen(ctx);
            return;
        }

        // ── Top header bar ────────────────────────────────────────────────────
        TopBottomPanel::top("header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("AuthSmith");
                ui.separator();
                ui.small(format!("Connected to {}", self.server_url));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Disconnect").clicked() {
                        self.disconnect();
                    }
                });
            });
        });

        // ── Tab bar ───────────────────────────────────────────────────────────
        TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let was = self.active_tab;

                if ui.selectable_label(was == Tab::Users, "👤  Users").clicked()
                    && was != Tab::Users
                {
                    self.active_tab = Tab::Users;
                    if matches!(self.users, LoadState::Idle) {
                        self.load_users();
                    }
                }
                if ui
                    .selectable_label(was == Tab::Sessions, "🔑  Sessions")
                    .clicked()
                    && was != Tab::Sessions
                {
                    self.active_tab = Tab::Sessions;
                    if matches!(self.sessions, LoadState::Idle) {
                        self.load_sessions();
                    }
                }
                if ui
                    .selectable_label(was == Tab::AuditLog, "📋  Audit Log")
                    .clicked()
                    && was != Tab::AuditLog
                {
                    self.active_tab = Tab::AuditLog;
                    if matches!(self.audit, LoadState::Idle) {
                        self.load_audit();
                    }
                }
            });
        });

        // ── Content panel ─────────────────────────────────────────────────────
        CentralPanel::default().show(ctx, |ui| {
            let tab = self.active_tab;
            match tab {
                Tab::Users => views::users::show(self, ui),
                Tab::Sessions => views::sessions::show(self, ui),
                Tab::AuditLog => views::audit::show(self, ui),
            }
        });
    }
}
