//! Engine loading and scan execution shared by the CLI subcommands and the
//! interactive app.

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};
use scanner_core::{
    Disposition, Engine, HashSignatureDb, Quarantine, ScanOptions, ScanReport, ScanSummary,
    Scanner, Severity, YaraEngine,
};

use crate::ui;

/// Inputs needed to construct the detection engine.
pub struct EngineConfig {
    pub hashes: PathBuf,
    pub rules: PathBuf,
    pub no_yara: bool,
}

/// Build the engine, returning it plus (hash_count, yara_file_count) for display.
///
/// External content (MSI install / explicit `--hashes`/`--rules`) is preferred;
/// otherwise the signatures embedded in the binary are used, so a standalone
/// `talos.exe` works with no files alongside it.
pub fn load_engine(cfg: &EngineConfig) -> Result<(Engine, usize, usize)> {
    let hashes = if cfg.hashes.is_file() {
        HashSignatureDb::from_file(&cfg.hashes)
            .with_context(|| format!("loading hash database {}", cfg.hashes.display()))?
    } else {
        HashSignatureDb::from_str_db(crate::embedded::HASHDB)
            .context("loading embedded hash database")?
    };
    let hash_count = hashes.len();

    let (yara, yara_files) = if cfg.no_yara {
        (None, 0)
    } else {
        let engine = if cfg.rules.is_dir() {
            YaraEngine::from_dir(&cfg.rules)
                .with_context(|| format!("compiling YARA rules in {}", cfg.rules.display()))?
        } else {
            YaraEngine::from_sources(crate::embedded::YARA_RULES.iter().copied())
                .context("compiling embedded YARA rules")?
        };
        let files = engine.source_files();
        (Some(engine), files)
    };

    Ok((Engine::new(hashes, yara), hash_count, yara_files))
}

/// Output/behavior knobs for a scan run.
pub struct ScanParams {
    pub json: bool,
    pub show_clean: bool,
    pub max_size_mib: u64,
    pub follow_symlinks: bool,
    /// Worker threads for directory scans (0 = all cores).
    pub threads: usize,
}

/// Result of a scan run.
pub struct ScanOutcome {
    pub summary: ScanSummary,
    /// Malicious reports, retained so the caller can offer quarantine.
    pub threats: Vec<ScanReport>,
}

/// Scan every target, printing per-file results, and collect threats.
pub fn run_scan(engine: &Engine, targets: &[PathBuf], params: &ScanParams) -> ScanOutcome {
    let options = ScanOptions {
        max_content_bytes: params.max_size_mib.saturating_mul(1024 * 1024),
        follow_symlinks: params.follow_symlinks,
        max_depth: None,
        threads: params.threads,
    };
    let scanner = Scanner::with_options(engine, options);

    let mut summary = ScanSummary::default();
    let mut threats = Vec::new();
    let started = Instant::now();

    {
        let mut handle = |report: ScanReport| {
            summary.record(&report);
            if params.json {
                if report.is_malicious() || report.error.is_some() || params.show_clean {
                    if let Ok(line) = serde_json::to_string(&report) {
                        println!("{line}");
                    }
                }
            } else {
                print_human(&report, params.show_clean);
            }
            if report.is_malicious() {
                threats.push(report);
            }
        };

        for target in targets {
            if target.is_dir() {
                // Parallel, multi-core scan for directories.
                for report in scanner.scan_tree_parallel(target) {
                    handle(report);
                }
            } else {
                handle(scanner.scan_file(target));
            }
        }
    }

    summary.duration_ms = started.elapsed().as_millis() as u64;
    ScanOutcome { summary, threats }
}

/// Quarantine all collected threats into `dir`; returns the count quarantined.
pub fn quarantine_threats(threats: &[ScanReport], dir: &Path) -> Result<usize> {
    if threats.is_empty() {
        return Ok(0);
    }
    let store = Quarantine::open(dir).context("opening quarantine store")?;
    let mut count = 0;
    for report in threats {
        let Some(hashes) = &report.hashes else {
            continue;
        };
        match store.quarantine_file(
            Path::new(&report.path),
            &hashes.sha256,
            report.size,
            report.detections.clone(),
        ) {
            Ok(_) => count += 1,
            Err(e) => eprintln!("  could not quarantine {}: {e}", report.path),
        }
    }
    Ok(count)
}

pub fn print_summary(summary: &ScanSummary) {
    let malicious = if summary.malicious > 0 {
        ui::red(&summary.malicious.to_string())
    } else {
        summary.malicious.to_string()
    };
    let suspicious = if summary.suspicious > 0 {
        ui::yellow(&summary.suspicious.to_string())
    } else {
        summary.suspicious.to_string()
    };
    let throughput = if summary.duration_ms > 0 && summary.bytes_scanned > 0 {
        let mib = summary.bytes_scanned as f64 / (1024.0 * 1024.0);
        let secs = summary.duration_ms as f64 / 1000.0;
        format!(" · {:.1} MiB/s", mib / secs)
    } else {
        String::new()
    };
    eprintln!(
        "\nscanned {} file(s), {malicious} malicious, {suspicious} suspicious, {} skipped, {} error(s) in {} ms{throughput}",
        summary.files_scanned, summary.skipped, summary.errors, summary.duration_ms
    );
}

fn print_human(report: &ScanReport, show_clean: bool) {
    match report.disposition {
        Disposition::Malicious => {
            for d in &report.detections {
                println!(
                    "[{}] {} :: {} ({:?})",
                    colored_sev(d.severity),
                    report.path,
                    d.name,
                    d.kind
                );
            }
        }
        Disposition::Suspicious => {
            for d in &report.detections {
                println!(
                    "[{}] {} :: {} ({:?})",
                    ui::yellow("SUSPECT"),
                    report.path,
                    d.name,
                    d.kind
                );
            }
        }
        Disposition::Error => eprintln!(
            "[{}] {}: {}",
            ui::red("error"),
            report.path,
            report.error.as_deref().unwrap_or("unknown error")
        ),
        Disposition::Skipped => {
            if show_clean {
                println!("[{}] {}", ui::dim("skip "), report.path);
            }
        }
        Disposition::Clean => {
            if show_clean {
                println!("[{}] {}", ui::green("clean"), report.path);
            }
        }
    }
}

fn colored_sev(s: Severity) -> String {
    match s {
        Severity::Low => ui::dim("LOW "),
        Severity::Medium => ui::yellow("MED "),
        Severity::High => ui::magenta("HIGH"),
        Severity::Critical => ui::red("CRIT"),
    }
}
