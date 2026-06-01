//! Talos EPP — endpoint protection app (Phase 1 MVP).
//!
//! Launched with **no arguments** it opens the interactive app (menu-driven).
//! Subcommands provide automation. Exit codes (clamscan-compatible):
//!   0 = clean, 1 = threat detected, 2 = error.

mod agent;
mod interactive;
mod paths;
mod runner;
mod ui;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use scanner_core::Quarantine;

use runner::{EngineConfig, ScanParams};

#[derive(Parser, Debug)]
#[command(name = "talos", version, about = "Talos EPP — endpoint protection")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Scan a path, or a built-in profile (--profile quick|full).
    Scan(ScanArgs),
    /// Manage the quarantine vault.
    Quarantine {
        /// Quarantine store directory (defaults to the per-machine store).
        #[arg(long)]
        dir: Option<PathBuf>,
        #[command(subcommand)]
        action: QuarantineAction,
    },
    /// Explain how signature updates are delivered.
    Update,
    /// Self-test: scan an EICAR sample to verify detection works end-to-end.
    Selftest,
}

#[derive(Args, Debug)]
struct ScanArgs {
    /// Path to scan (omit when using --profile).
    path: Option<PathBuf>,
    /// Built-in scan profile.
    #[arg(long, value_enum)]
    profile: Option<Profile>,
    /// Quarantine detected threats automatically.
    #[arg(long)]
    quarantine: bool,
    /// Emit one JSON object per reported file (NDJSON).
    #[arg(long)]
    json: bool,
    /// Also report clean/skipped files.
    #[arg(long)]
    show_clean: bool,
    /// Max file size (MiB) to load for content/YARA inspection.
    #[arg(long, default_value_t = 128)]
    max_size_mib: u64,
    /// Follow symbolic links.
    #[arg(long)]
    follow_symlinks: bool,
    /// Disable the YARA layer (hash-only).
    #[arg(long)]
    no_yara: bool,
    /// Override the hash database path.
    #[arg(long)]
    hashes: Option<PathBuf>,
    /// Override the YARA rules directory.
    #[arg(long)]
    rules: Option<PathBuf>,
    /// Override the quarantine store directory.
    #[arg(long)]
    quarantine_dir: Option<PathBuf>,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum Profile {
    Quick,
    Full,
}

#[derive(Subcommand, Debug)]
enum QuarantineAction {
    /// List quarantined items.
    List,
    /// Restore an item by id (to its original location, or --to <path>).
    Restore {
        id: String,
        #[arg(long)]
        to: Option<PathBuf>,
    },
    /// Permanently delete one item by id, or --all.
    Purge {
        id: Option<String>,
        #[arg(long)]
        all: bool,
    },
}

fn main() -> ExitCode {
    match Cli::parse().command {
        None => match interactive::run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(e),
        },
        Some(Command::Scan(args)) => cmd_scan(args),
        Some(Command::Quarantine { dir, action }) => cmd_quarantine(dir, action),
        Some(Command::Update) => {
            print_update_info();
            ExitCode::SUCCESS
        }
        Some(Command::Selftest) => cmd_selftest(),
    }
}

/// EICAR standard anti-malware test string (harmless industry test vector).
const EICAR: &[u8] = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;

fn cmd_selftest() -> ExitCode {
    let result = (|| -> Result<bool> {
        let cfg = EngineConfig {
            hashes: paths::default_hashes(),
            rules: paths::default_rules(),
            no_yara: false,
        };
        let (engine, hash_count, yara_files) = runner::load_engine(&cfg)?;
        println!("engine: {hash_count} hash signature(s), {yara_files} YARA file(s)");

        let dir = std::env::temp_dir().join(format!("talos-selftest-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let sample = dir.join("eicar-selftest.com");
        std::fs::write(&sample, EICAR)?;

        let params = ScanParams {
            json: false,
            show_clean: false,
            max_size_mib: 128,
            follow_symlinks: false,
        };
        let outcome = runner::run_scan(&engine, std::slice::from_ref(&sample), &params);

        let _ = std::fs::remove_file(&sample);
        let _ = std::fs::remove_dir(&dir);
        Ok(outcome.summary.malicious >= 1)
    })();

    match result {
        Ok(true) => {
            println!("SELFTEST PASSED — EICAR detected.");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            eprintln!("SELFTEST FAILED — EICAR not detected!");
            ExitCode::from(2)
        }
        Err(e) => fail(e),
    }
}

fn cmd_scan(args: ScanArgs) -> ExitCode {
    let outcome = (|| -> Result<bool> {
        let targets = resolve_targets(&args)?;
        let cfg = EngineConfig {
            hashes: args.hashes.clone().unwrap_or_else(paths::default_hashes),
            rules: args.rules.clone().unwrap_or_else(paths::default_rules),
            no_yara: args.no_yara,
        };
        let (engine, hash_count, yara_files) = runner::load_engine(&cfg)?;
        if !args.json {
            eprintln!("talos: {hash_count} hash signature(s), {yara_files} YARA file(s)");
        }

        let params = ScanParams {
            json: args.json,
            show_clean: args.show_clean,
            max_size_mib: args.max_size_mib,
            follow_symlinks: args.follow_symlinks,
        };
        let outcome = runner::run_scan(&engine, &targets, &params);
        agent::AgentState::record_scan(
            outcome.summary.files_scanned,
            outcome.summary.malicious,
            outcome.summary.suspicious,
        );

        if args.quarantine && !outcome.threats.is_empty() {
            let dir = args
                .quarantine_dir
                .clone()
                .unwrap_or_else(paths::default_quarantine_dir);
            let n = runner::quarantine_threats(&outcome.threats, &dir)?;
            eprintln!("quarantined {n} threat(s) into {}", dir.display());
        }
        if !args.json {
            runner::print_summary(&outcome.summary);
        }
        Ok(outcome.summary.malicious > 0)
    })();

    match outcome {
        Ok(true) => ExitCode::from(1),
        Ok(false) => ExitCode::SUCCESS,
        Err(e) => fail(e),
    }
}

fn resolve_targets(args: &ScanArgs) -> Result<Vec<PathBuf>> {
    if let Some(profile) = args.profile {
        let targets = match profile {
            Profile::Quick => paths::quick_scan_paths(),
            Profile::Full => paths::full_scan_roots(),
        };
        if targets.is_empty() {
            anyhow::bail!("no scan targets found for the selected profile");
        }
        Ok(targets)
    } else if let Some(path) = &args.path {
        if !path.exists() {
            anyhow::bail!("path does not exist: {}", path.display());
        }
        Ok(vec![path.clone()])
    } else {
        anyhow::bail!("provide a PATH or --profile quick|full");
    }
}

fn cmd_quarantine(dir: Option<PathBuf>, action: QuarantineAction) -> ExitCode {
    let dir = dir.unwrap_or_else(paths::default_quarantine_dir);
    let result = (|| -> Result<()> {
        let store = Quarantine::open(&dir)?;
        match action {
            QuarantineAction::List => {
                let items = store.list()?;
                if items.is_empty() {
                    println!("quarantine is empty ({})", dir.display());
                } else {
                    println!("{} item(s) in {}:", items.len(), dir.display());
                    for e in items {
                        let names: Vec<&str> =
                            e.detections.iter().map(|d| d.name.as_str()).collect();
                        println!("  {}  {}  [{}]", e.id, e.original_path, names.join(", "));
                    }
                }
            }
            QuarantineAction::Restore { id, to } => {
                let path = store.restore(&id, to.as_deref())?;
                println!("restored to {}", path.display());
            }
            QuarantineAction::Purge { id, all } => {
                if all {
                    let n = store.purge_all()?;
                    println!("purged {n} item(s)");
                } else if let Some(id) = id {
                    store.purge(&id)?;
                    println!("purged {id}");
                } else {
                    anyhow::bail!("specify an id or --all");
                }
            }
        }
        Ok(())
    })();

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(e),
    }
}

fn print_update_info() {
    println!("Signature updates are delivered via the secure, staged update channel");
    println!("(delta + TUF integrity) on a 48h baseline plus an emergency channel.");
    println!("See docs/03-secure-updates.md. (Online update client lands in a later phase.)");
}

fn fail(e: anyhow::Error) -> ExitCode {
    eprintln!("error: {e:#}");
    ExitCode::from(2)
}
