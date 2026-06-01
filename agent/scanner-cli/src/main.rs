//! Sentinel EPP — command-line scanner front-end (Phase 1 MVP).
//!
//! Exit codes (clamscan-compatible):
//!   0 = clean, 1 = malicious detected, 2 = error.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;
use scanner_core::{
    Disposition, Engine, HashSignatureDb, ScanOptions, ScanReport, ScanSummary, Scanner, Severity,
    YaraEngine,
};

/// Sentinel EPP user-mode scanner (hash signatures + YARA).
#[derive(Parser, Debug)]
#[command(name = "sentinel-scan", version, about)]
struct Cli {
    /// File or directory to scan.
    path: PathBuf,

    /// Hash-signature database (`<sha256>  Family.Name` per line).
    #[arg(long, default_value = "signatures/hashes/baseline.hashdb")]
    hashes: PathBuf,

    /// Directory of YARA rules (*.yar / *.yara), compiled recursively.
    #[arg(long, default_value = "signatures/yara")]
    rules: PathBuf,

    /// Disable the YARA layer (hash-only scan).
    #[arg(long)]
    no_yara: bool,

    /// Emit one JSON object per reported file (NDJSON) on stdout.
    #[arg(long)]
    json: bool,

    /// Also report clean/skipped files.
    #[arg(long)]
    show_clean: bool,

    /// Max file size (MiB) to load into memory for content/YARA inspection.
    #[arg(long, default_value_t = 128)]
    max_size_mib: u64,

    /// Follow symbolic links during traversal.
    #[arg(long)]
    follow_symlinks: bool,

    /// Suppress the trailing summary line.
    #[arg(long, short)]
    quiet: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: &Cli) -> Result<ExitCode> {
    if !cli.path.exists() {
        anyhow::bail!("path does not exist: {}", cli.path.display());
    }

    let hashes = HashSignatureDb::from_file(&cli.hashes)
        .with_context(|| format!("loading hash database {}", cli.hashes.display()))?;

    let yara = if cli.no_yara {
        None
    } else {
        Some(
            YaraEngine::from_dir(&cli.rules)
                .with_context(|| format!("compiling YARA rules in {}", cli.rules.display()))?,
        )
    };

    if !cli.quiet && !cli.json {
        let rules_note = match yara.as_ref() {
            Some(y) => format!("{} YARA file(s)", y.source_files()),
            None => "YARA disabled".to_string(),
        };
        eprintln!(
            "sentinel-scan: loaded {} hash signature(s), {}",
            hashes.len(),
            rules_note
        );
    }

    let engine = Engine::new(hashes, yara);
    let options = ScanOptions {
        max_content_bytes: cli.max_size_mib.saturating_mul(1024 * 1024),
        follow_symlinks: cli.follow_symlinks,
        max_depth: None,
    };
    let scanner = Scanner::with_options(&engine, options);

    let mut summary = ScanSummary::default();
    let mut found_malicious = false;
    let started = Instant::now();

    {
        let mut handle = |report: ScanReport| {
            summary.record(&report);
            if report.is_malicious() {
                found_malicious = true;
            }
            if cli.json {
                let interesting = report.is_malicious() || report.error.is_some() || cli.show_clean;
                if interesting {
                    if let Ok(line) = serde_json::to_string(&report) {
                        println!("{line}");
                    }
                }
            } else {
                print_human(&report, cli.show_clean);
            }
        };

        if cli.path.is_dir() {
            scanner.scan_path(&cli.path, &mut handle);
        } else {
            handle(scanner.scan_file(&cli.path));
        }
    }

    summary.duration_ms = started.elapsed().as_millis() as u64;

    if !cli.quiet {
        if cli.json {
            eprintln!("{}", serde_json::to_string(&summary).unwrap_or_default());
        } else {
            eprintln!(
                "\nscanned {} file(s), {} malicious, {} skipped, {} error(s) in {} ms",
                summary.files_scanned,
                summary.malicious,
                summary.skipped,
                summary.errors,
                summary.duration_ms
            );
        }
    }

    Ok(if found_malicious {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
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
