# 08 — Agent Service Architecture

Talos is moving from "a GUI that scans" to a proper **endpoint agent**: an
always-on background service that hosts protection, with the GUI and CLI as
**thin clients** that drive it over local IPC. This is the same split the
established products use (e.g. Bitdefender's `vsserv`/`bdagent` service with a
separate UI), and it's what makes real-time protection robust — it runs at boot,
survives user logoff, and isn't tied to a window being open.

> **Status.** Implemented and CI-validated today (Linux + Windows): the agent
> process, the **named-pipe / Unix-socket IPC**, the CLI client, the **Windows
> Service** control handler, **MSI service registration**, and the **GUI
> thin-client** (live service status + activity events, with real-time, firewall
> and web-protection controls routed through the service). The remaining
> *Roadmap* items (service self-protection, the kernel tier) need signed kernel
> drivers. Nothing here is faked.
>
> **IPC hardening:** the channel is a non-network local socket gated by an OS ACL
> (`0600` Unix socket / SYSTEM-Administrators pipe DACL); the token check is
> **constant-time**; framed messages are capped at **4 MiB**; and the agent runs
> **at most one client-initiated scan at a time**.

## Components

| Crate / binary | Role |
| --- | --- |
| `talos-agent` (`agent/talos-agent`) | The service host. Loads the engine, runs the real-time on-access monitor (with auto-quarantine) and the ransomware-canary guard, and serves client requests. |
| `talos-ipc` (`agent/talos-ipc`) | The shared wire protocol: request/response types, JSON framing, and the named-pipe / Unix-socket transport (`interprocess`). Used by the agent (server) and every client. |
| `talos` (`agent/scanner-cli`) | `talos agent …` subcommands that drive the running service instead of spinning up their own engine. |
| `talos-gui` (`agent/talos-gui`) | A thin client of the agent — live status, activity events, and real-time/firewall/web-protection controls — with an embedded-engine fallback when no service is installed. |

## Local IPC

Clients reach the agent over a **named pipe** (Windows) / **Unix-domain socket**
(Linux) — never a network socket — gated by OS access control plus a
**per-session token**:

1. On startup the agent binds the local socket (`\\.\pipe\talos-agent` on
   Windows; `~/.local/share/talos-epp/agent.sock` at mode `0600` on Linux),
   generates a token, and writes the socket **name + token** to a private
   **endpoint file** (`…/agent.endpoint`, `0600` on Linux).
2. A client reads that file to learn the socket name and token.
3. Each request is one **length-prefixed JSON** message wrapping the token plus
   a [`Request`]; the agent validates the token (constant-time) and replies with
   one [`Response`]. A wrong token is rejected as `unauthorized`.

Because the channel is a non-network local socket gated by an OS ACL — the
`0600` socket file on Linux, the SYSTEM/Administrators DACL of a
LocalSystem-created pipe on Windows — only a privileged local caller can drive
the agent. The cross-platform socket comes from the `interprocess` crate; the
Linux path is real Unix sockets, so the whole transport is tested off-Windows
and the identical API is exercised on the Windows CI job.

### Protocol surface

```
Request  → Ping | GetStatus | StartScan{paths,quarantine} | ListQuarantine
           | Restore{id} | SetRealtime{on} | SetFirewall{on}
           | FirewallBlock{ip} | FirewallUnblock{ip} | SetWebProtection{on}
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

## Roadmap (needs signed kernel drivers — Phase 2, per docs/01)

- **Service self-protection** — anti-malware **PPL** anchored by an **ELAM**
  driver so the service can't be killed by a standard admin.
- **Kernel tier** — file-system minifilter (pre-exec blocking + AMSI), WFP
  network filter, and VSS-backed ransomware rollback.
- **Windows pipe DACL** — an explicit SYSTEM/Administrators security descriptor
  on the named pipe (today it relies on the LocalSystem default DACL).

[`Request`]: ../agent/talos-ipc/src/proto.rs
[`Response`]: ../agent/talos-ipc/src/proto.rs
