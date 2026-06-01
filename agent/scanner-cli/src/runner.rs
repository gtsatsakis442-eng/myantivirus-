//! Engine loading and scan execution shared by the CLI subcommands and the
//! interactive app.

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};
use scanner_core::{
    Disposition, Engine, HashSignatureDb, Quarantine, ScanOptions, ScanReport, ScanSummary,
    Scanner, Severity, YaraEngine,
};

/// Inputs needed to construct the detection engine.
pub struct EngineConfig {
    pub hashes: PathBuf,
    pub rules: PathBuf,
    pub no_yara: bool,
}

/// Build the engine, returning it plus (hash_count, yara_file_count) for display.
pub fn load_engine(cfg: &EngineConfig) -> Result<(Engine, usize, usize)> {
    let hashes = HashSignatureDb::from_file(&cfg.hashes)
        .with_context(|| format!("loading hash database {}", cfg.hashes.display()))?;
    let hash_count = hashes.len();

    let (yara, yara_files) = if cfg.no_yara {
        (None, 0)
    } else {
        let engine = YaraEngine::from_dir(&cfg.rules)
            .with_context(|| format!("compiling YARA rules in {}", cfg.rules.display()))?;
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
                scanner.scan_path(target, &mut handle);
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
    eprintln!(
        "\nscanned {} file(s), {} malicious, {} skipped, {} error(s) in {} ms",
        summary.files_scanned,
        summary.malicious,
        summary.skipped,
        summary.errors,
        summary.duration_ms
    );
}

fn print_human(report: &ScanReport, show_clean: bool) {
    match report.disposition {
        Disposition::Malicious => {
            for d in &report.detections {
                println!(
                    "[{}] {} :: {} ({:?})",
                    sev_label(d.severity),
                    report.path,
                    d.name,
                    d.kind
                );
            }
        }
        Disposition::Error => eprintln!(
            "[error] {}: {}",
            report.path,
            report.error.as_deref().unwrap_or("unknown error")
        ),
        Disposition::Skipped => {
            if show_clean {
                println!("[skip ] {}", report.path);
            }
        }
        Disposition::Clean => {
            if show_clean {
                println!("[clean] {}", report.path);
            }
        }
    }
}

fn sev_label(s: Severity) -> &'static str {
    match s {
        Severity::Low => "LOW ",
        Severity::Medium => "MED ",
        Severity::High => "HIGH",
        Severity::Critical => "CRIT",
    }
}
