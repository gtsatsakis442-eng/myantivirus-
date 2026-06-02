//! Interactive enterprise console — what you get when the `.exe` is launched
//! with no arguments (e.g., double-clicked).

use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::Result;
use scanner_core::Quarantine;

use crate::agent::{self, AgentInfo};
use crate::runner::{self, EngineConfig, ScanParams};
use crate::{paths, ui};

pub fn run() -> Result<()> {
    let info = AgentInfo::load();
    ui::banner(&info.version);
    dashboard(&info);

    loop {
        menu();
        let choice = prompt(&ui::bold("Select> "))?;
        match choice.trim() {
            "1" => scan(paths::quick_scan_paths(), "Quick")?,
            "2" => {
                if confirm("Full system scan can take a long time. Continue? [y/N] ")? {
                    scan(paths::full_scan_roots(), "Full")?;
                }
            }
            "3" => {
                let input = prompt("Path to scan> ")?;
                let trimmed = input.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let path = PathBuf::from(trimmed);
                if path.exists() {
                    scan(vec![path], "Custom")?;
                } else {
                    println!(
                        "  {}",
                        ui::yellow(&format!("path does not exist: {trimmed}"))
                    );
                }
            }
            "4" => quarantine_menu()?,
            "5" => update_info(),
            "6" => about(),
            "7" => help(),
            "8" => dashboard(&info),
            "0" | "q" | "quit" | "exit" => {
                println!("{}", ui::dim("Goodbye."));
                break;
            }
            other => println!("  {}", ui::yellow(&format!("unknown option: {other}"))),
        }
    }
    Ok(())
}

/// Render the agent status dashboard.
fn dashboard(info: &AgentInfo) {
    let inv = agent::inventory();
    let state = agent::AgentState::load();

    ui::section("Agent Status");
    ui::kv("Product", &ui::bold("Talos EPP — Enterprise"));
    ui::kv("Version", &info.version);

    let management = if info.managed() {
        let tenant = info.tenant.as_deref().unwrap_or("unknown");
        ui::green(&format!("Managed  (tenant {tenant})"))
    } else {
        ui::yellow("Unmanaged (local)")
    };
    ui::kv("Management", &management);
    if let Some(server) = &info.server {
        ui::kv("Console", server);
    }
    ui::kv("Update ring", &info.update_ring);
    ui::kv(
        "Protection",
        &format!(
            "{}  ·  real-time: {}",
            ui::green("On-demand active"),
            ui::dim("Phase 2")
        ),
    );
    ui::kv(
        "Signatures",
        &format!(
            "{} hashes · {} YARA files",
            inv.hash_signatures, inv.yara_files
        ),
    );
    let quarantine = if inv.quarantined > 0 {
        ui::yellow(&format!("{} item(s)", inv.quarantined))
    } else {
        "0 items".to_string()
    };
    ui::kv("Quarantine", &quarantine);

    let last = if state.last_scan_unix == 0 {
        ui::dim("never")
    } else {
        format!(
            "{}  ({} files, {} malicious, {} suspicious)",
            ui::time_ago(state.last_scan_unix),
            state.last_files,
            state.last_malicious,
            state.last_suspicious
        )
    };
    ui::kv("Last scan", &last);
}

fn menu() {
    ui::section("Actions");
    item("1", "Quick Scan", "Downloads, Desktop, Temp, AppData …");
    item("2", "Full Scan", "entire system");
    item("3", "Custom Scan", "choose a file or folder");
    item("4", "Quarantine", "list / restore / purge isolated files");
    ui::section("System");
    item("5", "Update info", "how signatures are delivered");
    item("6", "About", "product information");
    item("7", "Help", "how to use the console");
    item("8", "Refresh status", "redraw the dashboard");
    item("0", "Exit", "");
}

fn item(key: &str, name: &str, hint: &str) {
    let label = format!("{:<14}", name);
    if hint.is_empty() {
        println!("  {} {}", ui::bold(&format!("[{key}]")), label);
    } else {
        println!(
            "  {} {} {}",
            ui::bold(&format!("[{key}]")),
            label,
            ui::dim(hint)
        );
    }
}

fn scan(targets: Vec<PathBuf>, label: &str) -> Result<()> {
    if targets.is_empty() {
        println!(
            "  {}",
            ui::yellow(&format!("no targets found for {label} scan."))
        );
        return Ok(());
    }
    println!(
        "{}",
        ui::dim(&format!(
            "Running {label} scan over {} location(s)…",
            targets.len()
        ))
    );

    let cfg = EngineConfig {
        hashes: paths::default_hashes(),
        rules: paths::default_rules(),
        no_yara: false,
    };
    let (engine, hashes, yara_files) = match runner::load_engine(&cfg) {
        Ok(v) => v,
        Err(e) => {
            println!("  {}", ui::red(&format!("engine load failed: {e:#}")));
            return Ok(());
        }
    };
    println!(
        "  {}",
        ui::dim(&format!(
            "engine: {hashes} hash signatures, {yara_files} YARA files"
        ))
    );

    let params = ScanParams {
        json: false,
        show_clean: false,
        max_size_mib: 128,
        follow_symlinks: false,
        threads: 0,
    };
    let outcome = runner::run_scan(&engine, &targets, &params);
    agent::AgentState::record_scan(
        outcome.summary.files_scanned,
        outcome.summary.malicious,
        outcome.summary.suspicious,
    );
    runner::print_summary(&outcome.summary);

    if !outcome.threats.is_empty()
        && confirm(&format!(
            "Quarantine {} detected threat(s)? [y/N] ",
            outcome.threats.len()
        ))?
    {
        let dir = paths::default_quarantine_dir();
        match runner::quarantine_threats(&outcome.threats, &dir) {
            Ok(n) => println!("  {}", ui::green(&format!("quarantined {n} item(s)"))),
            Err(e) => println!("  {}", ui::red(&format!("quarantine failed: {e:#}"))),
        }
    }
    Ok(())
}

fn quarantine_menu() -> Result<()> {
    let dir = paths::default_quarantine_dir();
    let store = match Quarantine::open(&dir) {
        Ok(q) => q,
        Err(e) => {
            println!("  {}", ui::red(&format!("cannot open quarantine: {e:#}")));
            return Ok(());
        }
    };
    let items = store.list()?;
    if items.is_empty() {
        ui::section("Quarantine");
        println!("  {}", ui::dim(&format!("empty ({})", dir.display())));
        return Ok(());
    }
    ui::section("Quarantine");
    for (i, e) in items.iter().enumerate() {
        println!(
            "  {} {}  {}",
            ui::bold(&format!("[{i}]")),
            e.original_path,
            ui::dim(&e.id)
        );
    }
    println!(
        "  {}",
        ui::dim("commands: r <n> restore · p <n> purge · pa purge-all · b back")
    );

    let cmd = prompt(&ui::bold("quarantine> "))?;
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    match parts.as_slice() {
        ["r", n] => match parse_idx(n, items.len()) {
            Some(i) => {
                let path = store.restore(&items[i].id, None)?;
                println!(
                    "  {}",
                    ui::green(&format!("restored to {}", path.display()))
                );
            }
            None => println!("  {}", ui::yellow("bad index")),
        },
        ["p", n] => match parse_idx(n, items.len()) {
            Some(i) => {
                store.purge(&items[i].id)?;
                println!("  {}", ui::green(&format!("purged {}", items[i].id)));
            }
            None => println!("  {}", ui::yellow("bad index")),
        },
        ["pa"] => {
            let n = store.purge_all()?;
            println!("  {}", ui::green(&format!("purged {n} item(s)")));
        }
        ["b"] | [] => {}
        _ => println!("  {}", ui::yellow("unknown command")),
    }
    Ok(())
}

fn parse_idx(s: &str, len: usize) -> Option<usize> {
    s.parse::<usize>().ok().filter(|i| *i < len)
}

fn about() {
    ui::section("About");
    println!("  Multi-layered detection: hash signatures + YARA + static heuristics,");
    println!("  including inspection inside ZIP archives.");
    println!("  Detected files can be quarantined (isolated) and later restored.");
    println!(
        "  {}",
        ui::dim("Roadmap: real-time kernel sensor, ML, and cloud — see docs/.")
    );
}

fn help() {
    ui::section("Help");
    println!("  [1] Quick Scan  — Downloads, Desktop, Temp, AppData (fast).");
    println!("  [2] Full Scan   — the whole system (can take a while).");
    println!("  [3] Custom Scan — enter any file or folder path.");
    println!("  [4] Quarantine  — review isolated threats; restore or delete.");
    println!("  [8] Refresh     — redraw the status dashboard.");
    println!();
    println!("  Malicious files can be quarantined (isolated + removed) and");
    println!("  restored if a false positive. 'Suspicious' heuristic results are");
    println!("  shown for awareness but never auto-removed. ZIP archives are");
    println!("  scanned inside. Full guide: docs/USAGE.md.");
}

fn update_info() {
    ui::section("Updates");
    println!("  Signatures update via the secure, staged channel (delta + TUF");
    println!("  integrity), on a 48h baseline plus an emergency channel.");
    println!(
        "  {}",
        ui::dim("See docs/03-secure-updates.md. Online client lands in a later phase.")
    );
}

fn prompt(p: &str) -> Result<String> {
    print!("\n{p}");
    io::stdout().flush()?;
    let mut line = String::new();
    let n = io::stdin().read_line(&mut line)?;
    if n == 0 {
        // EOF (no console / piped input ended): behave as "exit".
        return Ok("0".to_string());
    }
    Ok(line)
}

fn confirm(p: &str) -> Result<bool> {
    let answer = prompt(p)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}
