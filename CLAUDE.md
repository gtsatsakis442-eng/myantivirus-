# Talos EPP — Claude Code Project Intelligence

## What this project is

Production-grade **Endpoint Protection Platform** written in Rust. Ships as:
- `talos-gui` — egui/eframe desktop app (dark enterprise UI)
- `talos-agent` — always-on Windows Service / Linux daemon
- `scanner-cli` — headless CLI for scripted scans
- `scanner-core` — shared detection engine (the "brain")
- `talos-ipc` — Unix socket / named-pipe IPC protocol between components

Target: Windows primary, Linux fully supported. No `unsafe` in our code — only in audited deps (`goblin`, `yara-x`).

## Workspace layout

```
agent/
  scanner-core/   # detection engine: hashing, YARA, heuristics, behavior, firewall, web, feeds
  talos-agent/    # daemon: realtime, scheduler, canaries, IPC server
  talos-gui/      # egui GUI: dashboard, protection, scan, quarantine, activity, intel, settings
  talos-ipc/      # wire protocol (Request/Response enums, client helper)
  scanner-cli/    # CLI frontend
signatures/
  hashes/         # SHA-256 hash databases (.hashdb)
  yara/           # YARA rule files (.yar)
docs/             # architecture docs
```

## Essential commands

```bash
# Build everything
cargo build

# Build just the GUI (fastest iteration loop)
cargo build -p talos-gui

# Clippy (always run before committing)
cargo clippy -p talos-gui -p scanner-core

# Tests
cargo test -p scanner-core

# Run the GUI locally
cargo run -p talos-gui
```

## Current version & branch

- Workspace version: `0.13.0` (all crates share it via `workspace.package.version`)
- Dev branch: `claude/dazzling-lovelace-koRl2`
- Release workflow: `.github/workflows/release.yml` — triggers on push to `main`, updates existing `v0.13.0` tag and `latest` rolling release via `softprops/action-gh-release@v2`
- **Never push to main directly** — always work on the dev branch, create PR, squash-merge

## Architecture: detection layers (scanner-core)

1. **Hash signatures** (`hashing.rs`, `signatures.rs`) — SHA-256 exact match against `.hashdb` files
2. **YARA rules** (`yara_engine.rs`) — pattern matching via `yara-x`
3. **PE heuristics** (`heuristics.rs`) — static packing/injection/W^X checks
4. **Behavioral analysis** (`behavior.rs`) — CAPA-style import/string capability inference, MITRE ATT&CK tagged
5. **LOLBin detection** (`lolbin.rs`) — abuse of legitimate tools
6. **Archive inspection** (`archive.rs`) — ZIP unpacking with zip-bomb guard
7. **Threat feeds** (`feeds.rs`) — abuse.ch hashes + YARA feed updates; Ed25519 signed optional channel
8. **Firewall** (`firewall.rs`) — OS firewall orchestration (netsh/iptables); baseline port+IP blocks + feed sync + custom rules
9. **Web protection** (`webprotect.rs`) — URLhaus hosts-file sinkhole
10. **Realtime** (`realtime.rs`) — fanotify (Linux) / ReadDirectoryChangesW (Windows) on-access scan
11. **Ransomware guard** (`ransom_guard.rs`) — canary file decoy detection

## Key constants (scanner-core/src/firewall.rs)

```rust
BASELINE_PORTS  // 19 TCP ports: Metasploit 4444, Quasar 4782, njRAT 5552, AsyncRAT 6606/7707/8808,
                // IRC 6666/6667/6697, Tor 9001/9030/9050/9051/9150, NetBus 12345,
                // Back Orifice 31337, XMRig 14444/14433, leet 1337
BASELINE_BLOCKS // 8 Tor directory-authority IPs (moria1, tor26, dizum, gabelmoo, …)
KNOWN_FEEDS     // 4 threat feeds: Feodo C2 ×2, Spamhaus DROP, Spamhaus EDROP
TAG = "TalosBlock"
FEED_CHAIN = "TALOS_C2"
BASELINE_CHAIN = "TALOS_BASELINE"
```

## IPC protocol (talos-ipc/src/proto.rs)

`Request` enum (client → agent):
- `Ping`, `GetStatus`, `StartScan { paths, quarantine }`, `ListQuarantine`
- `Restore { id }`, `SetRealtime { on }`, `SetFirewall { on }`
- `FirewallBlock { ip }`, `FirewallUnblock { ip }`, `SetWebProtection { on }`
- `GetEvents { since }`, `Shutdown`

`Response` enum: `Pong`, `Status(Status)`, `ScanStarted`, `Quarantine`, `Events`, `Ack`, `Error`

`Status` struct: `realtime`, `firewall`, `firewall_blocked`, `web_protection`, `web_blocked`, `hash_signatures`, `yara_files`, `quarantined`, `last_scan_unix`, `threats_blocked`, `uptime_secs`

## GUI views (talos-gui/src/main.rs)

`View` enum: `Dashboard | Protection | Scan | Quarantine | Activity | Intel | Settings | About`

Key `TalosApp` fields:
- `config: TalosConfig` — persisted settings (auto-saved on change)
- `agent_status: Option<talos_ipc::Status>` — polled every 2s via IPC
- `admin_rx: Option<Receiver<engine_glue::AdminMsg>>` — in-process firewall/web result
- `admin_busy: bool` — gate: only one admin action at a time
- `local_fw_on / local_fw_blocked / local_web_on / local_web_blocked` — in-process state when no agent
- `new_port_rule: String` / `new_ip_rule: String` — custom rule inputs
- `custom_path / new_exclusion / firewall_ip` — other transient inputs

Pattern for deferred actions inside egui closures:
```rust
let mut flag: Option<T> = None;
card(ui, CARD, |ui| {
    if button.clicked() { flag = Some(value); }
});
if let Some(v) = flag { /* use self here */ }
```

## Config (talos-gui/src/config.rs)

`TalosConfig` persisted to `<data_dir>/config.json`. Key fields:
- `max_size_mib`, `threads`, `follow_symlinks`, `scan_archives`, `heuristics`, `behavior`
- `exclusions: Vec<String>`, `dark_theme`, `schedule: Schedule`
- `firewall_autostart: bool` (default `true`), `web_autostart: bool` (default `true`)
- `custom_blocked_ports: Vec<u16>` — user port rules
- `custom_blocked_ips: Vec<String>` — user IP/CIDR rules

`data_dir()`: `%PROGRAMDATA%\Talos EPP` (Windows) or `~/.local/share/talos-epp` (Linux)

All fields have `#[serde(default)]` — adding new fields never breaks existing config files.

## Daemon background tasks (talos-agent/src/daemon.rs)

- `spawn_realtime()` — always-on on-access scan + auto-quarantine
- `spawn_canaries()` — ransomware canary file monitoring
- `spawn_autostart()` — applies firewall+web protection at boot when `firewall_autostart`/`web_autostart`
- `spawn_scheduler()` — runs Quick Scan on Daily/Weekly cadence; state in `<data>/scheduler.state`

## engine_glue.rs admin actions (talos-gui/src/engine_glue.rs)

All return `Receiver<AdminMsg>` and run on a background thread:
- `start_firewall_sync()` — apply baseline + sync all 4 feeds
- `start_firewall_flush()` — remove all Talos rules
- `start_firewall_block(ip)` / `start_firewall_unblock(ip)` — single IP
- `start_firewall_block_port(port)` / `start_firewall_unblock_port(port)` — single TCP port
- `start_web_sync()` / `start_web_clear()` — URLhaus hosts sinkhole

`AdminMsg`: `Firewall { on, blocked: Option<usize>, note }` | `Web { on, blocked, note }` | `Failed(String)`

## agent_link.rs fire-and-forget IPC calls (talos-gui/src/agent_link.rs)

Used when the agent service is running (GUI defers to it rather than applying rules in-process):
- `set_realtime(on)`, `set_firewall(on)`, `set_web_protection(on)`
- `block_ip(ip)`, `unblock_ip(ip)`

## UI palette

```rust
BG     = #090b10   PANEL  = #0e1117   CARD   = #151921
TEXT   = #f0f2f5   DIM    = #8a94a3
ACCENT = #ff2d3a   GREEN  = #00e676   AMBER  = #ff9100
```

Helper widgets: `card()`, `module_card()`, `module_toggle()`, `stat_tile()`, `primary_button()`, `secondary_button()`, `nav()`, `nav_section()`, `heading()`

## Coding conventions

- **No unsafe** in our crates (`#![forbid(unsafe_code)]` in scanner-core)
- **No comments** explaining what code does — only why (hidden constraints, surprising invariants)
- **No error handling for impossible cases** — trust Rust + framework guarantees
- **No premature abstraction** — three similar lines > a wrapper
- **`#[serde(default)]`** on every config struct field for forward-compat
- Clippy clean: fix all new warnings before merging. Pre-existing warnings in `lolbin.rs` (2 collapsible-if) are known and untouched.

## Signed feed updates

`TALOS_SIGNED_FEED_URL` env var → `fetch_verified()` downloads `url` + `url.sig` (hex 64-byte raw Ed25519 sig), verifies against `TALOS_VERIFYING_KEY` in `feeds.rs`. Replace the test-vector key before production shipping.

## Merge workflow (important)

After each squash-merge to main, the dev branch retains the pre-squash commits. This creates conflicts on the next PR. Fix:

```bash
git fetch origin main
# identify the pre-squash commit (same message as the squash, on the branch but not main)
git rebase --onto origin/main <pre-squash-sha>
git push --force-with-lease origin claude/dazzling-lovelace-koRl2
```

## What's next (Phase 2)

- Windows kernel minifilter for pre-execution blocking
- ML-based behavioral scoring
- Ransomware rollback via VSS
- Per-URL in-browser filtering
- `FirewallBlockPort` / `FirewallUnblockPort` IPC requests (currently custom port rules are in-process only)
