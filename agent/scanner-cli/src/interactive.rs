//! Interactive, menu-driven app mode — what you get when the `.exe` is launched
//! with no arguments (e.g., double-clicked).

use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::Result;
use scanner_core::Quarantine;

use crate::paths;
use crate::runner::{self, EngineConfig, ScanParams};

pub fn run() -> Result<()> {
    banner();
    loop {
        menu();
        let choice = prompt("Select> ")?;
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
                    println!("  path does not exist: {trimmed}");
                }
            }
            "4" => quarantine_menu()?,
            "5" => update_info(),
            "6" => about(),
            "0" | "q" | "quit" | "exit" => {
                println!("Goodbye.");
                break;
            }
            other => println!("  unknown option: {other}"),
        }
        println!();
    }
    Ok(())
}

fn scan(targets: Vec<PathBuf>, label: &str) -> Result<()> {
    if targets.is_empty() {
        println!("  no targets found for {label} scan.");
        return Ok(());
    }
    println!("Running {label} scan over {} location(s)...", targets.len());

    let cfg = EngineConfig {
        hashes: paths::default_hashes(),
        rules: paths::default_rules(),
        no_yara: false,
    };
    let (engine, hashes, yara_files) = match runner::load_engine(&cfg) {
        Ok(v) => v,
        Err(e) => {
            println!("  engine load failed: {e:#}");
            return Ok(());
        }
    };
    println!("  engine: {hashes} hash signature(s), {yara_files} YARA file(s)");

    let params = ScanParams {
        json: false,
        show_clean: false,
        max_size_mib: 128,
        follow_symlinks: false,
    };
    let outcome = runner::run_scan(&engine, &targets, &params);
    runner::print_summary(&outcome.summary);

    if !outcome.threats.is_empty()
        && confirm(&format!(
            "Quarantine {} detected threat(s)? [y/N] ",
            outcome.threats.len()
        ))?
    {
        let dir = paths::default_quarantine_dir();
        match runner::quarantine_threats(&outcome.threats, &dir) {
            Ok(n) => println!("  quarantined {n} item(s) into {}", dir.display()),
            Err(e) => println!("  quarantine failed: {e:#}"),
        }
    }
    Ok(())
}

fn quarantine_menu() -> Result<()> {
    let dir = paths::default_quarantine_dir();
    let store = match Quarantine::open(&dir) {
        Ok(q) => q,
        Err(e) => {
            println!("  cannot open quarantine: {e:#}");
            return Ok(());
        }
    };
    let items = store.list()?;
    if items.is_empty() {
        println!("Quarantine is empty ({}).", dir.display());
        return Ok(());
    }
    println!("Quarantined items:");
    for (i, e) in items.iter().enumerate() {
        println!("  [{i}] {}  ({})", e.original_path, e.id);
    }
    println!("Commands: r <n> = restore, p <n> = purge, pa = purge all, b = back");

    let cmd = prompt("quarantine> ")?;
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    match parts.as_slice() {
        ["r", n] => match parse_idx(n, items.len()) {
            Some(i) => {
                let path = store.restore(&items[i].id, None)?;
                println!("  restored to {}", path.display());
            }
            None => println!("  bad index"),
        },
        ["p", n] => match parse_idx(n, items.len()) {
            Some(i) => {
                store.purge(&items[i].id)?;
                println!("  purged {}", items[i].id);
            }
            None => println!("  bad index"),
        },
        ["pa"] => {
            let n = store.purge_all()?;
            println!("  purged {n} item(s)");
        }
        ["b"] | [] => {}
        _ => println!("  unknown command"),
    }
    Ok(())
}

fn parse_idx(s: &str, len: usize) -> Option<usize> {
    s.parse::<usize>().ok().filter(|i| *i < len)
}

fn banner() {
    println!("============================================");
    println!(
        " Sentinel EPP — Endpoint Protection  v{}",
        env!("CARGO_PKG_VERSION")
    );
    println!("============================================");
}

fn menu() {
    println!("[1] Quick Scan      (Downloads, Temp, AppData, ...)");
    println!("[2] Full Scan       (entire system)");
    println!("[3] Custom Scan     (choose a path)");
    println!("[4] Quarantine      (list / restore / purge)");
    println!("[5] Update info");
    println!("[6] About");
    println!("[0] Exit");
}

fn about() {
    banner();
    println!("Multi-layered detection: exact hash signatures + YARA rules.");
    println!("Detected files can be quarantined (isolated) and later restored.");
    println!("Roadmap layers — real-time kernel sensor, ML, cloud — live in docs/.");
}

fn update_info() {
    println!("Signatures update via the secure, staged channel (delta + TUF integrity),");
    println!("on a 48h baseline plus an emergency channel. See docs/03-secure-updates.md.");
    println!("(The online update client lands in a later phase.)");
}

fn prompt(p: &str) -> Result<String> {
    print!("{p}");
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
