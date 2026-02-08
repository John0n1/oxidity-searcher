#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use egui::{Color32, RichText};
use egui_plot::{Line, Plot, PlotPoints};
use reqwest::blocking::Client;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

const POLL_INTERVAL: Duration = Duration::from_millis(1000);
const REQUEST_TIMEOUT: Duration = Duration::from_millis(1200);
const LOG_LIMIT: usize = 2000;
const METRIC_POINTS_LIMIT: usize = 240;

#[derive(Clone, Debug, PartialEq, Eq)]
enum ProcessState {
    Stopped,
    Starting,
    Running,
    Stopping,
}

#[derive(Clone, Debug)]
struct LaunchConfig {
    exe_path: PathBuf,
    workdir: PathBuf,
    config_path: PathBuf,
    metrics_bind: String,
    metrics_port: u16,
    metrics_token: String,
    dry_run: bool,
    strategy_enabled: bool,
    slippage_bps: Option<u64>,
}

impl LaunchConfig {
    fn base_url(&self) -> String {
        let bind = match self.metrics_bind.trim() {
            "" => "127.0.0.1",
            "0.0.0.0" => "127.0.0.1",
            other => other,
        };
        format!("http://{}:{}", bind, self.metrics_port)
    }
}

#[derive(Clone, Debug)]
enum SupervisorCommand {
    Start(LaunchConfig),
    Stop,
    Restart(LaunchConfig),
    SetLogLevel(String),
    Shutdown,
}

#[derive(Clone, Debug)]
enum SupervisorEvent {
    State(ProcessState),
    Dashboard(DashboardPayload),
    Logs(Vec<RemoteLogRecord>),
    Error(String),
    ProcessExited(String),
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct DashboardPayload {
    chain_id: u64,
    processed: u64,
    submitted: u64,
    skipped: u64,
    failed: u64,
    success_rate: f64,
    queue_depth: u64,
    queue_dropped: u64,
    queue_full: u64,
    queue_backpressure: u64,
    net_profit_eth: f64,
    history: Vec<BundleHistoryEntry>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct BundleHistoryEntry {
    tx: String,
    source: String,
    profit_eth: f64,
    gas_cost_eth: f64,
    net_eth: f64,
    timestamp_ms: i64,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct RemoteLogRecord {
    id: u64,
    timestamp: String,
    level: String,
    target: String,
    message: String,
}

#[derive(Clone, Debug, Default)]
struct MetricsPoint {
    t: f64,
    processed: f64,
    submitted: f64,
    failed: f64,
}

struct ControlPanelApp {
    cmd_tx: Sender<SupervisorCommand>,
    event_rx: Receiver<SupervisorEvent>,
    process_state: ProcessState,
    last_error: Option<String>,
    last_exit: Option<String>,
    dashboard: DashboardPayload,
    logs: VecDeque<RemoteLogRecord>,
    metrics_points: VecDeque<MetricsPoint>,
    app_started_at: Instant,

    exe_path: String,
    workdir: String,
    config_path: String,
    metrics_bind: String,
    metrics_port_input: String,
    metrics_token: String,
    dry_run: bool,
    strategy_enabled: bool,
    slippage_bps_input: String,
    log_level: String,
    auto_scroll_logs: bool,
}

impl ControlPanelApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_visuals(&cc.egui_ctx);

        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let default_exe = detect_default_executable();
        let default_workdir = cwd.to_string_lossy().to_string();
        let default_config = detect_default_config(&cwd);

        let (event_tx, event_rx) = mpsc::channel();
        let cmd_tx = spawn_supervisor(event_tx);

        Self {
            cmd_tx,
            event_rx,
            process_state: ProcessState::Stopped,
            last_error: None,
            last_exit: None,
            dashboard: DashboardPayload::default(),
            logs: VecDeque::new(),
            metrics_points: VecDeque::new(),
            app_started_at: Instant::now(),

            exe_path: default_exe.to_string_lossy().to_string(),
            workdir: default_workdir,
            config_path: default_config.to_string_lossy().to_string(),
            metrics_bind: "127.0.0.1".to_string(),
            metrics_port_input: "9000".to_string(),
            metrics_token: std::env::var("METRICS_TOKEN").unwrap_or_default(),
            dry_run: false,
            strategy_enabled: true,
            slippage_bps_input: String::new(),
            log_level: "info".to_string(),
            auto_scroll_logs: true,
        }
    }

    fn apply_events(&mut self) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                SupervisorEvent::State(state) => self.process_state = state,
                SupervisorEvent::Dashboard(payload) => {
                    self.dashboard = payload.clone();
                    self.metrics_points.push_back(MetricsPoint {
                        t: self.app_started_at.elapsed().as_secs_f64(),
                        processed: payload.processed as f64,
                        submitted: payload.submitted as f64,
                        failed: payload.failed as f64,
                    });
                    if self.metrics_points.len() > METRIC_POINTS_LIMIT {
                        self.metrics_points.pop_front();
                    }
                }
                SupervisorEvent::Logs(new_logs) => {
                    for log in new_logs {
                        self.logs.push_back(log);
                    }
                    while self.logs.len() > LOG_LIMIT {
                        self.logs.pop_front();
                    }
                }
                SupervisorEvent::Error(err) => self.last_error = Some(err),
                SupervisorEvent::ProcessExited(msg) => self.last_exit = Some(msg),
            }
        }
    }

    fn try_send_start(&mut self) {
        match self.build_launch_config() {
            Ok(cfg) => {
                self.last_error = None;
                let _ = self.cmd_tx.send(SupervisorCommand::Start(cfg));
            }
            Err(err) => self.last_error = Some(err),
        }
    }

    fn try_send_restart(&mut self) {
        match self.build_launch_config() {
            Ok(cfg) => {
                self.last_error = None;
                let _ = self.cmd_tx.send(SupervisorCommand::Restart(cfg));
            }
            Err(err) => self.last_error = Some(err),
        }
    }

    fn build_launch_config(&self) -> Result<LaunchConfig, String> {
        let workdir = PathBuf::from(self.workdir.trim());
        if !workdir.exists() {
            return Err(format!(
                "Working directory not found: {}",
                workdir.to_string_lossy()
            ));
        }
        if !workdir.is_dir() {
            return Err(format!(
                "Working directory is not a directory: {}",
                workdir.to_string_lossy()
            ));
        }

        let exe_input = PathBuf::from(self.exe_path.trim());
        let exe_path = if exe_input.is_absolute() {
            exe_input
        } else {
            workdir.join(exe_input)
        };
        if !exe_path.exists() {
            return Err(format!(
                "Executable not found: {}",
                exe_path.to_string_lossy()
            ));
        }

        let config_input = PathBuf::from(self.config_path.trim());
        let config_path = if config_input.is_absolute() {
            config_input
        } else {
            workdir.join(config_input)
        };
        if !config_path.exists() {
            return Err(format!(
                "Config file not found: {}",
                config_path.to_string_lossy()
            ));
        }

        let metrics_port = self
            .metrics_port_input
            .trim()
            .parse::<u16>()
            .map_err(|_| "Metrics port must be a valid u16 number".to_string())?;
        if metrics_port == 0 {
            return Err("Metrics port must be greater than 0".to_string());
        }

        let metrics_token = self.metrics_token.trim().to_string();
        if metrics_token.is_empty() {
            return Err("Metrics token is required".to_string());
        }

        let slippage_bps = if self.slippage_bps_input.trim().is_empty() {
            None
        } else {
            Some(
                self.slippage_bps_input
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| "Slippage BPS must be a valid number".to_string())?,
            )
        };

        Ok(LaunchConfig {
            exe_path,
            workdir,
            config_path,
            metrics_bind: self.metrics_bind.trim().to_string(),
            metrics_port,
            metrics_token,
            dry_run: self.dry_run,
            strategy_enabled: self.strategy_enabled,
            slippage_bps,
        })
    }

    fn process_state_badge(&self) -> (Color32, &'static str) {
        match self.process_state {
            ProcessState::Stopped => (Color32::from_rgb(150, 70, 70), "Stopped"),
            ProcessState::Starting => (Color32::from_rgb(185, 140, 60), "Starting"),
            ProcessState::Running => (Color32::from_rgb(60, 150, 90), "Running"),
            ProcessState::Stopping => (Color32::from_rgb(170, 105, 55), "Stopping"),
        }
    }

    fn show_top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading(RichText::new("Oxidity Control Panel").size(28.0));

            let (color, state_text) = self.process_state_badge();
            ui.add_space(12.0);
            ui.colored_label(
                color,
                RichText::new(format!("  {}  ", state_text))
                    .strong()
                    .background_color(Color32::from_rgba_unmultiplied(
                        color.r(),
                        color.g(),
                        color.b(),
                        40,
                    )),
            );
        });

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let can_start = matches!(self.process_state, ProcessState::Stopped);
            let can_stop = matches!(
                self.process_state,
                ProcessState::Running | ProcessState::Starting
            );

            if ui
                .add_enabled(
                    can_start,
                    egui::Button::new(RichText::new("Start").strong())
                        .fill(Color32::from_rgb(35, 104, 78)),
                )
                .clicked()
            {
                self.try_send_start();
            }

            if ui
                .add_enabled(
                    can_stop,
                    egui::Button::new(RichText::new("Stop").strong())
                        .fill(Color32::from_rgb(120, 56, 56)),
                )
                .clicked()
            {
                let _ = self.cmd_tx.send(SupervisorCommand::Stop);
            }

            if ui
                .add_enabled(
                    can_stop,
                    egui::Button::new("Restart").fill(Color32::from_rgb(66, 85, 120)),
                )
                .clicked()
            {
                self.try_send_restart();
            }

            ui.separator();
            egui::ComboBox::from_label("Log level")
                .selected_text(self.log_level.clone())
                .show_ui(ui, |ui| {
                    for level in ["trace", "debug", "info", "warn", "error"] {
                        ui.selectable_value(&mut self.log_level, level.to_string(), level);
                    }
                });
            if ui.button("Apply").clicked() {
                let _ = self
                    .cmd_tx
                    .send(SupervisorCommand::SetLogLevel(self.log_level.clone()));
            }
        });

        if let Some(exit) = &self.last_exit {
            ui.add_space(6.0);
            ui.colored_label(Color32::from_rgb(219, 170, 100), exit);
        }
        if let Some(err) = &self.last_error {
            ui.add_space(6.0);
            ui.colored_label(Color32::from_rgb(220, 95, 95), err);
        }
    }

    fn show_settings(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new("Runtime Settings")
            .default_open(true)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Executable");
                    ui.text_edit_singleline(&mut self.exe_path);
                });
                ui.horizontal(|ui| {
                    ui.label("Workdir");
                    ui.text_edit_singleline(&mut self.workdir);
                });
                ui.horizontal(|ui| {
                    ui.label("Config");
                    ui.text_edit_singleline(&mut self.config_path);
                });

                ui.horizontal(|ui| {
                    ui.label("Metrics bind");
                    ui.text_edit_singleline(&mut self.metrics_bind);
                    ui.label("Port");
                    ui.text_edit_singleline(&mut self.metrics_port_input);
                });
                ui.horizontal(|ui| {
                    ui.label("Metrics token");
                    ui.add(egui::TextEdit::singleline(&mut self.metrics_token).password(true));
                });
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.dry_run, "Dry run");
                    ui.checkbox(&mut self.strategy_enabled, "Strategy enabled");
                    ui.label("Slippage BPS");
                    ui.text_edit_singleline(&mut self.slippage_bps_input);
                });
            });
    }

    fn show_kpis(&self, ui: &mut egui::Ui) {
        ui.columns(4, |columns| {
            render_kpi_card(
                &mut columns[0],
                "Processed",
                self.dashboard.processed.to_string(),
                Color32::from_rgb(89, 163, 255),
            );
            render_kpi_card(
                &mut columns[1],
                "Submitted",
                self.dashboard.submitted.to_string(),
                Color32::from_rgb(92, 207, 150),
            );
            render_kpi_card(
                &mut columns[2],
                "Failed",
                self.dashboard.failed.to_string(),
                Color32::from_rgb(224, 96, 96),
            );
            render_kpi_card(
                &mut columns[3],
                "Net Profit ETH",
                format!("{:.6}", self.dashboard.net_profit_eth),
                Color32::from_rgb(222, 172, 82),
            );
        });

        ui.add_space(8.0);
        ui.columns(4, |columns| {
            render_kpi_card(
                &mut columns[0],
                "Success %",
                format!("{:.2}", self.dashboard.success_rate),
                Color32::from_rgb(98, 193, 160),
            );
            render_kpi_card(
                &mut columns[1],
                "Queue Depth",
                self.dashboard.queue_depth.to_string(),
                Color32::from_rgb(123, 174, 235),
            );
            render_kpi_card(
                &mut columns[2],
                "Queue Dropped",
                self.dashboard.queue_dropped.to_string(),
                Color32::from_rgb(233, 136, 97),
            );
            render_kpi_card(
                &mut columns[3],
                "Chain",
                self.dashboard.chain_id.to_string(),
                Color32::from_rgb(159, 132, 230),
            );
        });
    }

    fn show_metrics_plot(&self, ui: &mut egui::Ui) {
        let processed: PlotPoints<'_> = self
            .metrics_points
            .iter()
            .map(|p| [p.t, p.processed])
            .collect();
        let submitted: PlotPoints<'_> = self
            .metrics_points
            .iter()
            .map(|p| [p.t, p.submitted])
            .collect();
        let failed: PlotPoints<'_> = self
            .metrics_points
            .iter()
            .map(|p| [p.t, p.failed])
            .collect();

        Plot::new("throughput_plot")
            .height(180.0)
            .include_y(0.0)
            .allow_scroll(false)
            .allow_zoom(false)
            .show(ui, |plot_ui| {
                plot_ui.line(
                    Line::new(processed)
                        .name("processed")
                        .color(Color32::from_rgb(89, 163, 255)),
                );
                plot_ui.line(
                    Line::new(submitted)
                        .name("submitted")
                        .color(Color32::from_rgb(92, 207, 150)),
                );
                plot_ui.line(
                    Line::new(failed)
                        .name("failed")
                        .color(Color32::from_rgb(224, 96, 96)),
                );
            });
    }

    fn show_bundle_table(&self, ui: &mut egui::Ui) {
        ui.label(RichText::new("Recent Bundles").strong());
        egui::ScrollArea::vertical()
            .max_height(160.0)
            .show(ui, |ui| {
                for row in self.dashboard.history.iter().take(30) {
                    ui.horizontal_wrapped(|ui| {
                        ui.colored_label(
                            Color32::from_rgb(116, 196, 153),
                            format!("{:+.6} ETH", row.net_eth),
                        );
                        ui.label(format!("profit {:.6}", row.profit_eth));
                        ui.label(format!("gas {:.6}", row.gas_cost_eth));
                        ui.label(format!("source {}", row.source));
                        ui.monospace(format!("tx {}", short_hash(&row.tx)));
                        ui.label(format!("ts {}", row.timestamp_ms));
                    });
                    ui.separator();
                }
            });
    }

    fn show_logs(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Live Logs").strong());
            ui.checkbox(&mut self.auto_scroll_logs, "Auto-scroll");
            if ui.button("Clear").clicked() {
                self.logs.clear();
            }
        });

        egui::ScrollArea::vertical()
            .stick_to_bottom(self.auto_scroll_logs)
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                for log in &self.logs {
                    let level_color = level_color(&log.level);
                    ui.horizontal_wrapped(|ui| {
                        ui.colored_label(level_color, format!("{:>5}", log.level.to_uppercase()));
                        ui.monospace(format!("#{} {}", log.id, log.timestamp));
                        ui.label(
                            RichText::new(&log.target).color(Color32::from_rgb(132, 168, 206)),
                        );
                        ui.label(log.message.trim_matches('"'));
                    });
                }
            });
    }
}

impl eframe::App for ControlPanelApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.apply_events();

        egui::TopBottomPanel::top("top_panel")
            .resizable(false)
            .show(ctx, |ui| {
                self.show_top_bar(ui);
            });

        egui::SidePanel::left("left_panel")
            .resizable(true)
            .default_width(460.0)
            .show(ctx, |ui| {
                self.show_settings(ui);
                ui.add_space(10.0);
                self.show_kpis(ui);
                ui.add_space(10.0);
                self.show_metrics_plot(ui);
                ui.add_space(8.0);
                self.show_bundle_table(ui);
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            self.show_logs(ui);
        });

        ctx.request_repaint_after(Duration::from_millis(200));
    }
}

impl Drop for ControlPanelApp {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(SupervisorCommand::Shutdown);
    }
}

fn render_kpi_card(ui: &mut egui::Ui, title: &str, value: String, accent: Color32) {
    egui::Frame::default()
        .fill(Color32::from_rgb(18, 30, 43))
        .stroke(egui::Stroke::new(1.0, Color32::from_rgb(35, 58, 84)))
        .inner_margin(egui::Margin::same(10))
        .show(ui, |ui| {
            ui.colored_label(accent, RichText::new(title).strong());
            ui.label(RichText::new(value).size(23.0).strong());
        });
}

fn spawn_supervisor(event_tx: Sender<SupervisorEvent>) -> Sender<SupervisorCommand> {
    let (cmd_tx, cmd_rx) = mpsc::channel::<SupervisorCommand>();
    std::thread::spawn(move || supervisor_loop(cmd_rx, event_tx));
    cmd_tx
}

fn supervisor_loop(cmd_rx: Receiver<SupervisorCommand>, event_tx: Sender<SupervisorEvent>) {
    let client = match Client::builder().timeout(REQUEST_TIMEOUT).build() {
        Ok(c) => c,
        Err(e) => {
            let _ = event_tx.send(SupervisorEvent::Error(format!(
                "Failed to initialize HTTP client: {}",
                e
            )));
            return;
        }
    };

    let mut child: Option<Child> = None;
    let mut launch: Option<LaunchConfig> = None;
    let mut current_state = ProcessState::Stopped;
    let mut last_poll = Instant::now() - POLL_INTERVAL;
    let mut log_after: u64 = 0;

    loop {
        match cmd_rx.recv_timeout(Duration::from_millis(150)) {
            Ok(cmd) => match cmd {
                SupervisorCommand::Start(cfg) => {
                    if child.is_some() {
                        let _ = event_tx.send(SupervisorEvent::Error(
                            "Process already running".to_string(),
                        ));
                    } else {
                        match spawn_searcher(&cfg) {
                            Ok(spawned) => {
                                child = Some(spawned);
                                launch = Some(cfg);
                                log_after = 0;
                                emit_state(&event_tx, &mut current_state, ProcessState::Starting);
                                last_poll = Instant::now() - POLL_INTERVAL;
                            }
                            Err(e) => {
                                let _ = event_tx.send(SupervisorEvent::Error(e));
                                emit_state(&event_tx, &mut current_state, ProcessState::Stopped);
                            }
                        }
                    }
                }
                SupervisorCommand::Stop => {
                    stop_child(&mut child, &event_tx, &mut current_state);
                    launch = None;
                    log_after = 0;
                }
                SupervisorCommand::Restart(cfg) => {
                    stop_child(&mut child, &event_tx, &mut current_state);
                    launch = None;
                    log_after = 0;
                    match spawn_searcher(&cfg) {
                        Ok(spawned) => {
                            child = Some(spawned);
                            launch = Some(cfg);
                            emit_state(&event_tx, &mut current_state, ProcessState::Starting);
                            last_poll = Instant::now() - POLL_INTERVAL;
                        }
                        Err(e) => {
                            let _ = event_tx.send(SupervisorEvent::Error(e));
                        }
                    }
                }
                SupervisorCommand::SetLogLevel(level) => {
                    if let Some(cfg) = launch.as_ref() {
                        let url = format!("{}/log_level?level={}", cfg.base_url(), level);
                        if let Err(e) =
                            authorized_get::<serde_json::Value>(&client, &url, &cfg.metrics_token)
                        {
                            let _ = event_tx.send(SupervisorEvent::Error(format!(
                                "Failed to set log level: {}",
                                e
                            )));
                        }
                    } else {
                        let _ = event_tx.send(SupervisorEvent::Error(
                            "Process is not running; cannot set log level".to_string(),
                        ));
                    }
                }
                SupervisorCommand::Shutdown => {
                    stop_child(&mut child, &event_tx, &mut current_state);
                    break;
                }
            },
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }

        if let Some(running) = child.as_mut() {
            match running.try_wait() {
                Ok(Some(status)) => {
                    let msg = format!(
                        "Searcher exited with code {}",
                        status
                            .code()
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "unknown".to_string())
                    );
                    let _ = event_tx.send(SupervisorEvent::ProcessExited(msg));
                    child = None;
                    launch = None;
                    log_after = 0;
                    emit_state(&event_tx, &mut current_state, ProcessState::Stopped);
                    continue;
                }
                Ok(None) => {}
                Err(e) => {
                    let _ = event_tx.send(SupervisorEvent::Error(format!(
                        "Failed to inspect process state: {}",
                        e
                    )));
                }
            }
        }

        if child.is_some() && last_poll.elapsed() >= POLL_INTERVAL {
            last_poll = Instant::now();

            if let Some(cfg) = launch.as_ref() {
                let base = cfg.base_url();
                let health_url = format!("{}/health", base);
                let health_ok =
                    authorized_get::<serde_json::Value>(&client, &health_url, &cfg.metrics_token)
                        .is_ok();
                if health_ok {
                    emit_state(&event_tx, &mut current_state, ProcessState::Running);
                } else if current_state == ProcessState::Running {
                    emit_state(&event_tx, &mut current_state, ProcessState::Starting);
                }

                let dashboard_url = format!("{}/dashboard", base);
                if let Ok(payload) =
                    authorized_get::<DashboardPayload>(&client, &dashboard_url, &cfg.metrics_token)
                {
                    let _ = event_tx.send(SupervisorEvent::Dashboard(payload));
                }

                let logs_url = format!("{}/logs?after={}&limit=240", base, log_after);
                if let Ok(new_logs) =
                    authorized_get::<Vec<RemoteLogRecord>>(&client, &logs_url, &cfg.metrics_token)
                {
                    if let Some(last) = new_logs.last() {
                        log_after = last.id;
                    }
                    if !new_logs.is_empty() {
                        let _ = event_tx.send(SupervisorEvent::Logs(new_logs));
                    }
                }
            }
        }
    }
}

fn stop_child(
    child: &mut Option<Child>,
    event_tx: &Sender<SupervisorEvent>,
    current_state: &mut ProcessState,
) {
    if let Some(mut process) = child.take() {
        emit_state(event_tx, current_state, ProcessState::Stopping);
        if let Err(e) = process.kill() {
            let _ = event_tx.send(SupervisorEvent::Error(format!(
                "Failed to stop searcher process: {}",
                e
            )));
        }
        let _ = process.wait();
    }
    emit_state(event_tx, current_state, ProcessState::Stopped);
}

fn emit_state(event_tx: &Sender<SupervisorEvent>, current: &mut ProcessState, next: ProcessState) {
    if *current != next {
        *current = next.clone();
        let _ = event_tx.send(SupervisorEvent::State(next));
    }
}

fn spawn_searcher(cfg: &LaunchConfig) -> Result<Child, String> {
    let mut cmd = Command::new(&cfg.exe_path);
    cmd.current_dir(&cfg.workdir)
        .arg("--config")
        .arg(&cfg.config_path)
        .arg("--metrics-port")
        .arg(cfg.metrics_port.to_string())
        .env("METRICS_TOKEN", &cfg.metrics_token)
        .env("METRICS_BIND", &cfg.metrics_bind)
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    if cfg.dry_run {
        cmd.arg("--dry-run");
    }
    if !cfg.strategy_enabled {
        cmd.arg("--no-strategy");
    }
    if let Some(v) = cfg.slippage_bps {
        cmd.arg("--slippage-bps").arg(v.to_string());
    }

    cmd.spawn()
        .map_err(|e| format!("Failed to start searcher: {}", e))
}

fn authorized_get<T: DeserializeOwned>(
    client: &Client,
    url: &str,
    token: &str,
) -> Result<T, String> {
    let response = client
        .get(url)
        .bearer_auth(token)
        .send()
        .map_err(|e| format!("GET {} failed: {}", url, e))?;

    if !response.status().is_success() {
        return Err(format!("GET {} returned status {}", url, response.status()));
    }

    response
        .json::<T>()
        .map_err(|e| format!("GET {} invalid JSON: {}", url, e))
}

fn detect_default_executable() -> PathBuf {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let candidates = [
        cwd.join("oxidity-builder.exe"),
        cwd.join("target").join("debug").join("oxidity-builder.exe"),
        cwd.join("target")
            .join("release")
            .join("oxidity-builder.exe"),
    ];

    for c in candidates {
        if c.exists() {
            return c;
        }
    }

    PathBuf::from("oxidity-builder.exe")
}

fn detect_default_config(base_dir: &Path) -> PathBuf {
    let candidates = [
        base_dir.join("config.prod.toml"),
        base_dir.join("config.toml"),
        base_dir.join("config.dev.toml"),
        base_dir.join("config.testnet.toml"),
    ];
    for c in candidates {
        if c.exists() {
            return c;
        }
    }
    PathBuf::from("config.toml")
}

fn configure_visuals(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.window_fill = Color32::from_rgb(10, 16, 24);
    visuals.panel_fill = Color32::from_rgb(12, 20, 30);
    visuals.extreme_bg_color = Color32::from_rgb(8, 13, 20);
    visuals.override_text_color = Some(Color32::from_rgb(224, 232, 242));
    visuals.widgets.inactive.bg_fill = Color32::from_rgb(23, 35, 49);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(34, 53, 72);
    visuals.widgets.active.bg_fill = Color32::from_rgb(40, 63, 88);
    visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(16, 24, 35);
    visuals.selection.bg_fill = Color32::from_rgb(45, 109, 185);
    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(12.0, 8.0);
    style.spacing.window_margin = egui::Margin::same(10);
    style.visuals.window_stroke = egui::Stroke::new(1.0, Color32::from_rgb(30, 50, 72));
    ctx.set_style(style);
}

fn short_hash(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() <= 14 {
        return trimmed.to_string();
    }
    let start = &trimmed[..8];
    let end = &trimmed[trimmed.len().saturating_sub(6)..];
    format!("{}...{}", start, end)
}

fn level_color(level: &str) -> Color32 {
    match level.to_lowercase().as_str() {
        "trace" => Color32::from_rgb(160, 160, 160),
        "debug" => Color32::from_rgb(104, 166, 235),
        "info" => Color32::from_rgb(94, 208, 160),
        "warn" => Color32::from_rgb(230, 170, 90),
        "error" => Color32::from_rgb(232, 99, 99),
        _ => Color32::from_rgb(200, 200, 200),
    }
}

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Oxidity Control Panel")
            .with_inner_size([1400.0, 900.0])
            .with_min_inner_size([1150.0, 700.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Oxidity Control Panel",
        options,
        Box::new(|cc| Ok(Box::new(ControlPanelApp::new(cc)))),
    )
}
