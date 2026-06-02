//! Talos EPP — desktop GUI (egui/eframe). A self-contained, dark "security
//! console" front-end over the same engine the CLI uses.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod engine_glue;

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{SystemTime, UNIX_EPOCH};

use eframe::egui;
use egui::{Color32, RichText};
use scanner_core::{ScanReport, Severity};

use engine_glue::ScanMsg;

// ---- palette -------------------------------------------------------------
const BG: Color32 = Color32::from_rgb(0x12, 0x16, 0x1d);
const PANEL: Color32 = Color32::from_rgb(0x18, 0x1d, 0x26);
const CARD: Color32 = Color32::from_rgb(0x1f, 0x26, 0x31);
const TEXT: Color32 = Color32::from_rgb(0xe6, 0xe9, 0xef);
const DIM: Color32 = Color32::from_rgb(0x93, 0x9f, 0xb0);
const ACCENT: Color32 = Color32::from_rgb(0xe1, 0x1d, 0x2a); // Talos red
const GREEN: Color32 = Color32::from_rgb(0x2b, 0xd6, 0x6a);
const AMBER: Color32 = Color32::from_rgb(0xff, 0xb0, 0x20);

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([980.0, 660.0])
            .with_min_inner_size([820.0, 560.0])
            .with_title("Talos EPP — Endpoint Protection"),
        ..Default::default()
    };
    eframe::run_native(
        "Talos EPP",
        options,
        Box::new(|cc| {
            install_theme(&cc.egui_ctx);
            Ok(Box::new(TalosApp::new()))
        }),
    )
}

fn install_theme(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.panel_fill = PANEL;
    v.window_fill = PANEL;
    v.extreme_bg_color = BG;
    v.override_text_color = Some(TEXT);
    v.selection.bg_fill = ACCENT.linear_multiply(0.55);
    v.widgets.hovered.bg_fill = CARD;
    v.widgets.inactive.bg_fill = CARD;
    v.widgets.active.bg_fill = ACCENT;
    ctx.set_visuals(v);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.button_padding = egui::vec2(12.0, 8.0);
    ctx.set_style(style);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Dashboard,
    Scan,
    Quarantine,
    About,
}

#[derive(Clone, Copy)]
struct Done {
    files: u64,
    malicious: u64,
    suspicious: u64,
    ms: u64,
    bytes: u64,
}

struct TalosApp {
    view: View,
    version: String,
    tenant: Option<String>,
    hashes: usize,
    yara: usize,
    quarantined: usize,

    custom_path: String,

    rx: Option<Receiver<ScanMsg>>,
    scanning: bool,
    scan_label: String,
    scanned: u64,
    current: String,
    threats: Vec<ScanReport>,
    last: Option<Done>,
    last_scan_unix: u64,
    status: String,

    q_items: Vec<scanner_core::QuarantineEntry>,
    q_loaded: bool,
}

impl TalosApp {
    fn new() -> Self {
        let (hashes, yara, quarantined) = engine_glue::inventory_counts();
        Self {
            view: View::Dashboard,
            version: env!("CARGO_PKG_VERSION").to_string(),
            tenant: std::env::var("TALOS_TENANT").ok().filter(|s| !s.is_empty()),
            hashes,
            yara,
            quarantined,
            custom_path: String::new(),
            rx: None,
            scanning: false,
            scan_label: String::new(),
            scanned: 0,
            current: String::new(),
            threats: Vec::new(),
            last: None,
            last_scan_unix: 0,
            status: "Ready.".to_string(),
            q_items: Vec::new(),
            q_loaded: false,
        }
    }

    fn refresh_inventory(&mut self) {
        let (h, y, q) = engine_glue::inventory_counts();
        self.hashes = h;
        self.yara = y;
        self.quarantined = q;
    }

    fn start(&mut self, targets: Vec<PathBuf>, label: &str) {
        if self.scanning {
            return;
        }
        if targets.is_empty() {
            self.status = format!("No targets found for {label} scan.");
            return;
        }
        self.threats.clear();
        self.scanned = 0;
        self.current.clear();
        self.last = None;
        self.scan_label = label.to_string();
        self.scanning = true;
        self.status = format!("Running {label} scan…");
        self.rx = Some(engine_glue::start_scan(targets));
        self.view = View::Scan;
    }

    fn poll(&mut self, ctx: &egui::Context) {
        let mut finished = false;
        if let Some(rx) = &self.rx {
            loop {
                match rx.try_recv() {
                    Ok(ScanMsg::Progress { scanned, current }) => {
                        self.scanned = scanned;
                        self.current = current;
                    }
                    Ok(ScanMsg::Threat(r)) => {
                        self.scanned += 1;
                        if self.threats.len() < 5000 {
                            self.threats.push(*r);
                        }
                    }
                    Ok(ScanMsg::Done {
                        files,
                        malicious,
                        suspicious,
                        ms,
                        bytes,
                    }) => {
                        self.last = Some(Done {
                            files,
                            malicious,
                            suspicious,
                            ms,
                            bytes,
                        });
                        self.last_scan_unix = now_unix();
                        self.scanning = false;
                        self.status = format!(
                            "{} scan complete — {malicious} malicious, {suspicious} suspicious in {files} files",
                            self.scan_label
                        );
                        finished = true;
                    }
                    Ok(ScanMsg::Failed(e)) => {
                        self.scanning = false;
                        self.status = format!("Scan failed: {e}");
                        finished = true;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        self.scanning = false;
                        finished = true;
                        break;
                    }
                }
            }
        }
        if finished {
            self.rx = None;
            self.refresh_inventory();
        }
        if self.scanning {
            ctx.request_repaint();
        }
    }

    fn reload_quarantine(&mut self) {
        self.q_items = scanner_core::Quarantine::open(engine_glue::quarantine_dir())
            .and_then(|q| q.list())
            .unwrap_or_default();
        self.q_loaded = true;
    }
}

impl eframe::App for TalosApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll(ctx);

        egui::SidePanel::left("nav")
            .exact_width(210.0)
            .resizable(false)
            .frame(egui::Frame::none().fill(BG).inner_margin(16.0))
            .show(ctx, |ui| self.sidebar(ui));

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(PANEL).inner_margin(22.0))
            .show(ctx, |ui| match self.view {
                View::Dashboard => self.dashboard(ui),
                View::Scan => self.scan_view(ui),
                View::Quarantine => self.quarantine_view(ui),
                View::About => self.about(ui),
            });
    }
}

impl TalosApp {
    fn sidebar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.label(RichText::new("◆ TALOS").color(ACCENT).size(24.0).strong());
        ui.label(RichText::new("Endpoint Protection").color(DIM).size(12.0));
        ui.add_space(18.0);

        nav(ui, &mut self.view, View::Dashboard, "Dashboard");
        nav(ui, &mut self.view, View::Scan, "Scan");
        nav(ui, &mut self.view, View::Quarantine, "Quarantine");
        nav(ui, &mut self.view, View::About, "About");

        ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
            ui.add_space(4.0);
            ui.label(
                RichText::new(format!("v{}", self.version))
                    .color(DIM)
                    .size(11.0),
            );
            match &self.tenant {
                Some(t) => ui.label(
                    RichText::new(format!("Managed · {t}"))
                        .color(GREEN)
                        .size(11.0),
                ),
                None => ui.label(RichText::new("Unmanaged (local)").color(DIM).size(11.0)),
            };
        });
    }

    fn dashboard(&mut self, ui: &mut egui::Ui) {
        heading(ui, "Dashboard");

        let threats = self.last.map(|d| d.malicious + d.suspicious).unwrap_or(0);
        let (status_col, title, subtitle) = if self.scanning {
            (AMBER, "Scan in progress", "Talos is inspecting your files…")
        } else if threats > 0 {
            (
                ACCENT,
                "Threats detected",
                "Review the Scan view and quarantine the findings.",
            )
        } else {
            (
                GREEN,
                "Protected",
                "On-demand engine ready · real-time sensor: Phase 2",
            )
        };

        card(ui, CARD, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("●").color(status_col).size(40.0));
                ui.add_space(8.0);
                ui.vertical(|ui| {
                    ui.label(RichText::new(title).color(TEXT).size(22.0).strong());
                    ui.label(RichText::new(subtitle).color(DIM).size(13.0));
                });
            });
        });

        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            stat(ui, "Signatures", &format!("{}", self.hashes), "hash rules");
            stat(ui, "YARA files", &format!("{}", self.yara), "rule sets");
            stat(
                ui,
                "Quarantine",
                &format!("{}", self.quarantined),
                "isolated",
            );
            stat(
                ui,
                "Last scan",
                &if self.last_scan_unix == 0 {
                    "never".to_string()
                } else {
                    time_ago(self.last_scan_unix)
                },
                "",
            );
        });

        ui.add_space(14.0);
        if primary_button(ui, "Run Quick Scan").clicked() {
            self.start(engine_glue::quick_scan_paths(), "Quick");
        }
        ui.add_space(6.0);
        ui.label(RichText::new(&self.status).color(DIM).size(12.0));
    }

    fn scan_view(&mut self, ui: &mut egui::Ui) {
        heading(ui, "Scan");

        ui.add_enabled_ui(!self.scanning, |ui| {
            ui.horizontal(|ui| {
                if primary_button(ui, "Quick Scan").clicked() {
                    self.start(engine_glue::quick_scan_paths(), "Quick");
                }
                if secondary_button(ui, "Full Scan").clicked() {
                    self.start(engine_glue::full_scan_roots(), "Full");
                }
            });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Custom path:").color(DIM));
                ui.add(
                    egui::TextEdit::singleline(&mut self.custom_path)
                        .desired_width(420.0)
                        .hint_text("C:\\Users\\me\\Downloads"),
                );
                if secondary_button(ui, "Scan").clicked() {
                    let trimmed = self.custom_path.trim().to_string();
                    let p = PathBuf::from(&trimmed);
                    if trimmed.is_empty() {
                        self.status = "Enter a path to scan.".to_string();
                    } else if !p.exists() {
                        self.status = format!("Path does not exist: {trimmed}");
                    } else {
                        self.start(vec![p], "Custom");
                    }
                }
            });
        });

        ui.add_space(10.0);
        card(ui, CARD, |ui| {
            if self.scanning {
                ui.horizontal(|ui| {
                    ui.add(egui::Spinner::new().color(ACCENT));
                    ui.label(
                        RichText::new(format!(
                            "Scanning… {} files · {} threats",
                            self.scanned,
                            self.threats.len()
                        ))
                        .color(TEXT)
                        .size(15.0),
                    );
                });
                ui.label(
                    RichText::new(truncate(&self.current, 80))
                        .color(DIM)
                        .size(11.0),
                );
            } else if let Some(d) = self.last {
                let mibps = if d.ms > 0 {
                    (d.bytes as f64 / 1_048_576.0) / (d.ms as f64 / 1000.0)
                } else {
                    0.0
                };
                ui.label(
                    RichText::new(format!(
                        "{} scan: {} files · {} malicious · {} suspicious · {} ms · {:.1} MiB/s",
                        self.scan_label, d.files, d.malicious, d.suspicious, d.ms, mibps
                    ))
                    .color(TEXT),
                );
            } else {
                ui.label(RichText::new("Choose a scan to begin.").color(DIM));
            }
        });

        if !self.threats.is_empty() {
            ui.add_space(8.0);
            let malicious = self.threats.iter().filter(|r| r.is_malicious()).count();
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("Detections ({})", self.threats.len()))
                        .color(TEXT)
                        .strong(),
                );
                if malicious > 0
                    && !self.scanning
                    && secondary_button(ui, &format!("Quarantine {malicious}")).clicked()
                {
                    match engine_glue::quarantine_reports(&self.threats) {
                        Ok(n) => {
                            self.status = format!("Quarantined {n} item(s).");
                            self.threats.retain(|r| !r.is_malicious());
                            self.q_loaded = false;
                            self.refresh_inventory();
                        }
                        Err(e) => self.status = format!("Quarantine failed: {e}"),
                    }
                }
            });

            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for r in &self.threats {
                        for d in &r.detections {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(sev_tag(d.severity))
                                        .color(sev_color(d.severity))
                                        .strong(),
                                );
                                ui.label(RichText::new(&r.path).color(TEXT).size(12.0));
                                ui.label(
                                    RichText::new(format!("→ {}", d.name)).color(DIM).size(12.0),
                                );
                            });
                        }
                    }
                });
        }
    }

    fn quarantine_view(&mut self, ui: &mut egui::Ui) {
        heading(ui, "Quarantine");
        if !self.q_loaded {
            self.reload_quarantine();
        }
        ui.horizontal(|ui| {
            if secondary_button(ui, "Refresh").clicked() {
                self.reload_quarantine();
            }
            ui.label(RichText::new(format!("{} item(s)", self.q_items.len())).color(DIM));
        });
        ui.add_space(6.0);

        if self.q_items.is_empty() {
            card(ui, CARD, |ui| {
                ui.label(RichText::new("Quarantine is empty.").color(DIM));
            });
            return;
        }

        enum Act {
            Restore,
            Purge,
        }
        let mut action: Option<(Act, String)> = None;

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for item in &self.q_items {
                    card(ui, CARD, |ui| {
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.label(RichText::new(&item.original_path).color(TEXT).size(12.0));
                                let names: Vec<&str> =
                                    item.detections.iter().map(|d| d.name.as_str()).collect();
                                ui.label(RichText::new(names.join(", ")).color(DIM).size(11.0));
                            });
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui.button(RichText::new("Delete").color(ACCENT)).clicked() {
                                        action = Some((Act::Purge, item.id.clone()));
                                    }
                                    if ui.button("Restore").clicked() {
                                        action = Some((Act::Restore, item.id.clone()));
                                    }
                                },
                            );
                        });
                    });
                }
            });

        if let Some((act, id)) = action {
            if let Ok(store) = scanner_core::Quarantine::open(engine_glue::quarantine_dir()) {
                let _ = match act {
                    Act::Restore => store.restore(&id, None).map(|_| ()),
                    Act::Purge => store.purge(&id),
                };
            }
            self.status = "Quarantine updated.".to_string();
            self.reload_quarantine();
            self.refresh_inventory();
        }
    }

    fn about(&mut self, ui: &mut egui::Ui) {
        heading(ui, "About");
        card(ui, CARD, |ui| {
            ui.label(
                RichText::new("Talos EPP — Endpoint Protection Platform")
                    .color(TEXT)
                    .size(16.0)
                    .strong(),
            );
            ui.label(RichText::new(format!("Version {}", self.version)).color(DIM));
            ui.add_space(8.0);
            ui.label(RichText::new("Detection layers").color(TEXT).strong());
            ui.label(RichText::new("• Hash signatures (SHA-256)").color(DIM));
            ui.label(
                RichText::new("• YARA rules (web shells, malicious PowerShell, …)").color(DIM),
            );
            ui.label(
                RichText::new("• Static PE heuristics (packing, injection imports, W^X)")
                    .color(DIM),
            );
            ui.label(RichText::new("• ZIP archive inspection (zip-bomb-guarded)").color(DIM));
            ui.add_space(8.0);
            ui.label(
                RichText::new(
                    "Detected files can be quarantined and restored. Real-time kernel sensor, \
                     ML and cloud are on the roadmap.",
                )
                .color(DIM),
            );
        });
    }
}

// ---- small widgets / helpers --------------------------------------------

fn nav(ui: &mut egui::Ui, current: &mut View, target: View, label: &str) {
    let selected = *current == target;
    let resp = ui.add_sized(
        [ui.available_width(), 36.0],
        egui::SelectableLabel::new(selected, RichText::new(label).size(15.0)),
    );
    if resp.clicked() {
        *current = target;
    }
}

fn heading(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).color(TEXT).size(26.0).strong());
    ui.add_space(12.0);
}

fn card<R>(ui: &mut egui::Ui, fill: Color32, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::none()
        .fill(fill)
        .rounding(10.0)
        .inner_margin(16.0)
        .show(ui, add)
        .inner
}

fn stat(ui: &mut egui::Ui, title: &str, value: &str, unit: &str) {
    egui::Frame::none()
        .fill(CARD)
        .rounding(10.0)
        .inner_margin(14.0)
        .show(ui, |ui| {
            ui.set_width(150.0);
            ui.label(RichText::new(title).color(DIM).size(12.0));
            ui.label(RichText::new(value).color(TEXT).size(22.0).strong());
            if !unit.is_empty() {
                ui.label(RichText::new(unit).color(DIM).size(11.0));
            }
        });
}

fn primary_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add_sized(
        [ui.available_width().min(220.0), 40.0],
        egui::Button::new(
            RichText::new(text)
                .color(Color32::WHITE)
                .size(15.0)
                .strong(),
        )
        .fill(ACCENT),
    )
}

fn secondary_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add_sized(
        [140.0, 36.0],
        egui::Button::new(RichText::new(text).color(TEXT)),
    )
}

fn sev_color(s: Severity) -> Color32 {
    match s {
        Severity::Low => DIM,
        Severity::Medium => AMBER,
        Severity::High => Color32::from_rgb(0xff, 0x6a, 0x3d),
        Severity::Critical => ACCENT,
    }
}

fn sev_tag(s: Severity) -> &'static str {
    match s {
        Severity::Low => "LOW ",
        Severity::Medium => "MED ",
        Severity::High => "HIGH",
        Severity::Critical => "CRIT",
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let kept: String = s
            .chars()
            .rev()
            .take(max)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("…{kept}")
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn time_ago(then: u64) -> String {
    let secs = now_unix().saturating_sub(then);
    match secs {
        0..=59 => "just now".to_string(),
        60..=3599 => format!("{} min ago", secs / 60),
        3600..=86_399 => format!("{} h ago", secs / 3600),
        _ => format!("{} d ago", secs / 86_400),
    }
}
