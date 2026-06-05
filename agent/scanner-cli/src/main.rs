//! Talos EPP — endpoint protection app (Phase 1 MVP).
//!
//! Launched with **no arguments** it opens the interactive app (menu-driven).
//! Subcommands provide automation. Exit codes (clamscan-compatible):
//!   0 = clean, 1 = threat detected, 2 = error.

mod agent;
mod embedded;
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
    /// Fetch & install signature feeds into the local store (broadens detection).
    Update(UpdateArgs),
    /// Look up a hash (or a file's hash) against a free threat-intel API.
    Lookup {
        /// A SHA-256 hash, or a path to a file (its SHA-256 is computed).
        target: String,
    },
    /// Real-time on-access monitoring: auto-scan files as they appear (user-mode).
    Watch {
        /// Folders to watch (default: the Quick-Scan high-risk locations).
        paths: Vec<PathBuf>,
    },
    /// Self-test: scan an EICAR sample to verify detection works end-to-end.
    Selftest,
}

#[derive(Args, Debug)]
struct UpdateArgs {
    /// Skip the abuse.ch MalwareBazaar hash feed (CC0).
    #[arg(long)]
    no_abuse_ch: bool,
    /// Skip the open YARA rule feeds.
    #[arg(long)]
    no_yara_feeds: bool,
    /// Also pull a ClamAV `.hsb` SHA-256 list from this URL (GPL).
    #[arg(long)]
    clamav_url: Option<String>,
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
    /// Worker threads for directory scans (0 = all CPU cores).
    #[arg(long, default_value_t = 0)]
    threads: usize,
    /// Follow symbolic links.
    #[arg(long)]
    follow_symlinks: bool,
    /// Disable the YARA layer (hash-only).
    #[arg(long)]
    no_yara: bool,
    /// Disable the static behavioral capability layer (CAPA-style).
    #[arg(long)]
    no_behavior: bool,
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
        Some(Command::Update(args)) => cmd_update(args),
        Some(Command::Lookup { target }) => cmd_lookup(target),
        Some(Command::Watch { paths }) => cmd_watch(paths),
        Some(Command::Selftest) => cmd_selftest(),
    }
}

fn cmd_lookup(target: String) -> ExitCode {
    let result = (|| -> Result<()> {
        // Accept either a SHA-256 directly or a path to a file.
        let sha = if target.len() == 64 && target.bytes().all(|b| b.is_ascii_hexdigit()) {
            target.clone()
        } else {
            let path = PathBuf::from(&target);
            if !path.is_file() {
                anyhow::bail!("not a SHA-256 hash or an existing file: {target}");
            }
            let bytes = std::fs::read(&path)?;
            scanner_core::hash_bytes(&bytes).sha256
        };
        eprintln!("Looking up {sha} …");
        let reports = scanner_core::lookup_hash(&sha)?;
        for report in &reports {
            println!(
                "[{}] {}",
                report.source,
                if report.found { "known" } else { "no record" }
            );
            for line in &report.lines {
                println!("  {line}");
            }
        }
        Ok(())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(e),
    }
}

fn cmd_watch(paths: Vec<PathBuf>) -> ExitCode {
    let targets = if paths.is_empty() {
        paths::quick_scan_paths()
    } else {
        paths
    };
    let result = (|| -> Result<()> {
        let (engine, _, _) = runner::load_engine(&EngineConfig::default())?;
        let scanner = scanner_core::Scanner::new(&engine);
        let watch = scanner_core::realtime::watch(&targets)?;
        eprintln!(
            "Real-time monitoring {} folder(s) — auto-scanning new/changed files. Ctrl-C to stop.",
            targets.len()
        );
        eprintln!("(user-mode on-access; kernel minifilter is Phase 2)");
        for path in watch.rx.iter() {
            let report = scanner.scan_file(&path);
            if report.is_malicious() || report.is_suspicious() {
                let names: Vec<&str> = report.detections.iter().map(|d| d.name.as_str()).collect();
                println!(
                    "[{}] {}  [{}]",
                    if report.is_malicious() {
                        "THREAT"
                    } else {
                        "SUSPECT"
                    },
                    report.path,
                    names.join(", ")
                );
            }
        }
        Ok(())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(e),
    }
}

fn cmd_update(args: UpdateArgs) -> ExitCode {
    let opts = scanner_core::UpdateOptions {
        abuse_ch: !args.no_abuse_ch,
        open_yara: !args.no_yara_feeds,
        clamav: args.clamav_url.is_some(),
        clamav_url: args.clamav_url,
        ..Default::default()
    };
    let store = paths::store_dir();
    eprintln!("Updating signatures into {} …", store.display());
    let report = scanner_core::feeds::update(&store, &opts);
    for m in &report.messages {
        println!("  {m}");
    }
    // Reload to report the new totals.
    match runner::load_engine(&EngineConfig::default()) {
        Ok((_, h, y)) => {
            println!("Definitions now: {h} hash signatures, {y} YARA files.");
            ExitCode::SUCCESS
        }
        Err(e) => fail(e),
    }
}

/// EICAR standard anti-malware test string (harmless industry test vector).
const EICAR: &[u8] = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;

fn cmd_selftest() -> ExitCode {
    let result = (|| -> Result<bool> {
        let cfg = EngineConfig::default();
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
            threads: 0,
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
            hashes: args.hashes.clone(),
            rules: args.rules.clone(),
            no_yara: args.no_yara,
        };
        let (mut engine, hash_count, yara_files) = runner::load_engine(&cfg)?;
        engine.set_behavior(!args.no_behavior);
        if !args.json {
            eprintln!("talos: {hash_count} hash signature(s), {yara_files} YARA file(s)");
        }

        let params = ScanParams {
            json: args.json,
            show_clean: args.show_clean,
            max_size_mib: args.max_size_mib,
            follow_symlinks: args.follow_symlinks,
            threads: args.threads,
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

fn fail(e: anyhow::Error) -> ExitCode {
    eprintln!("error: {e:#}");
    ExitCode::from(2)
}
