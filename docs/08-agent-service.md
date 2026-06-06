# 08 — Agent Service Architecture

Talos is moving from "a GUI that scans" to a proper **endpoint agent**: an
always-on background service that hosts protection, with the GUI and CLI as
**thin clients** that drive it over local IPC. This is the same split the
established products use (e.g. Bitdefender's `vsserv`/`bdagent` service with a
separate UI), and it's what makes real-time protection robust — it runs at boot,
survives user logoff, and isn't tied to a window being open.

> **Status.** Implemented and CI-validated today (Linux + Windows): the agent
> process, the IPC protocol, the CLI client, the **Windows Service** control
> handler, and **MSI service registration**. The MSI installs `talos-agent.exe`
> and registers it as an auto-start LocalSystem service. The remaining *Roadmap*
> items (GUI thin-client, named-pipe transport hardening, the kernel tier) are
> the next steps. Nothing here is faked.

## Components

| Crate / binary | Role |
| --- | --- |
| `talos-agent` (`agent/talos-agent`) | The service host. Loads the engine, runs the real-time on-access monitor (with auto-quarantine) and the ransomware-canary guard, and serves client requests. |
| `talos-ipc` (`agent/talos-ipc`) | The shared wire protocol: request/response types, JSON framing, and the loopback transport. Used by the agent (server) and every client. |
| `talos` (`agent/scanner-cli`) | Gains `talos agent …` subcommands that drive the running service instead of spinning up their own engine. |
| `talos-gui` (`agent/talos-gui`) | *(Roadmap)* becomes a thin client of the agent, with an embedded-engine fallback when no service is installed. |

## Local IPC

Clients reach the agent over a **loopback TCP** socket (`127.0.0.1`, an
OS-assigned ephemeral port) protected by a **per-session token**:

1. On startup the agent binds `127.0.0.1:0`, generates a token, and writes both
   to a private **endpoint file** — `…/Talos EPP/agent.endpoint` on Windows,
   `~/.local/share/talos-epp/agent.endpoint` on Linux (mode `0600`).
2. A client reads that file to learn the port and token.
3. Each request is one **length-prefixed JSON** message wrapping the token plus
   a [`Request`]; the agent validates the token and replies with one
   [`Response`]. A wrong token is rejected as `unauthorized`.

Loopback TCP is used (rather than OS named pipes / Unix sockets) because it is a
single `std::net` code path that behaves identically on Windows and Linux and is
fully testable. Hardening the transport to **named pipes / Unix sockets with OS
ACLs** is a Roadmap item; the protocol above does not change when that lands.

### Protocol surface

```
Request  → Ping | GetStatus | StartScan{paths,quarantine} | ListQuarantine
           | Restore{id} | SetRealtime{on} | SetFirewall{on}
           | GetEvents{since} | Shutdown
Response → Pong | Status{…} | ScanStarted{scan_id} | Quarantine{items}
           | Events{events,next} | Ack | Error{message}
```

`GetEvents{since}` is a cursor poll over the agent's rolling activity log, so a
client (status bar, dashboard) can stream new events without missing any.

## Using it

```sh
# Windows: install as an auto-start LocalSystem service (the MSI does this too).
talos-agent install
talos-agent uninstall

# Run in the foreground (any OS; engine + real-time + ransomware guard + IPC).
talos-agent run

# Query / drive the running service from any client:
talos-agent status            # or: talos agent status
talos-agent events            # or: talos agent events
talos agent scan ~/Downloads --quarantine
```

On Windows the MSI registers the **`TalosAgent`** service (auto-start,
LocalSystem), which the Service Control Manager launches as
`talos-agent.exe service-run`; a `Stop` cleanly trips the shared stop flag so
the IPC loop and worker threads wind down.

The agent watches the Quick-Scan high-risk locations, **auto-quarantines** a
malicious file the moment it lands, and raises a **ransomware alarm** if a
planted canary is tampered with — all recorded in the activity log that
`… events` prints and the GUI dashboard will show.

## Roadmap

- **GUI thin-client** — the dashboard connects to the agent for live status and
  control, falling back to its embedded engine when no service is present.
- **Transport hardening** — named pipe (Windows) / Unix socket (Linux) with a
  SYSTEM/Administrators-only ACL in place of loopback TCP.
- **Service self-protection** — anti-malware **PPL** anchored by an **ELAM**
  driver so the service can't be killed by a standard admin.
- **Kernel tier (Phase 2, per docs/01)** — file-system minifilter, WFP network
  filter, and VSS-backed ransomware rollback remain the kernel-driver effort.

[`Request`]: ../agent/talos-ipc/src/proto.rs
[`Response`]: ../agent/talos-ipc/src/proto.rs
