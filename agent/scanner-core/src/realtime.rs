//! Real-time on-access protection.
//!
//! Two backends, chosen by what the OS lets a user-mode process do — exactly
//! how the established products split it:
//!
//!  * **Enforcing (Linux · `fanotify`)** — intercepts every file **open** and
//!    **exec** *before* it proceeds (`FAN_OPEN_PERM` / `FAN_OPEN_EXEC_PERM`),
//!    scans the bytes, and returns `FAN_ALLOW` or **`FAN_DENY`** — so a
//!    malicious file is **blocked from being opened or executed in real time**.
//!    This is the same mechanism ClamAV's `clamonacc` uses. Requires
//!    `CAP_SYS_ADMIN` (root). See [`enforce`].
//!  * **Monitoring (all platforms · `notify`)** — reacts to create/modify after
//!    the fact so the agent can auto-scan (and the GUI auto-quarantines). It
//!    does not block the I/O. See [`watch`].
//!
//! On **Windows**, true pre-execution *blocking* needs a kernel file-system
//! **minifilter** (+ **AMSI** for scripts/memory) — a signed-driver effort that
//! is Phase 2 (docs/01). Until then Windows uses the monitoring backend with
//! immediate auto-quarantine.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver};

use notify::{EventKind, RecursiveMode, Watcher as _};

use crate::error::{Result, ScanError};

/// Whether this platform supports the **enforcing** (blocking) backend in user
/// mode. True on Linux (via `fanotify`, with root); false elsewhere (Windows
/// pre-execution blocking is the Phase-2 kernel minifilter).
pub fn can_enforce() -> bool {
    cfg!(target_os = "linux")
}

// ---- Monitoring backend (cross-platform) ---------------------------------

/// A live folder watch. **Dropping it stops watching.** Read [`Watch::rx`] for
/// changed file paths (the OS notifier coalesces rapid events).
pub struct Watch {
    _watcher: notify::RecommendedWatcher,
    /// Paths of files that were created or modified under the watched roots.
    pub rx: Receiver<PathBuf>,
}

/// Begin watching `paths` (recursively). Non-existent paths are skipped; an
/// error is returned only if *nothing* could be watched.
pub fn watch(paths: &[PathBuf]) -> Result<Watch> {
    let (tx, rx) = channel::<PathBuf>();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(event) = res {
            if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                for p in event.paths {
                    if p.is_file() {
                        let _ = tx.send(p);
                    }
                }
            }
        }
    })
    .map_err(|e| ScanError::Update(format!("real-time init failed: {e}")))?;

    let mut watched = 0usize;
    for p in paths {
        if p.exists() && watcher.watch(p, RecursiveMode::Recursive).is_ok() {
            watched += 1;
        }
    }
    if watched == 0 {
        return Err(ScanError::Update(
            "real-time: no existing folders to watch".to_string(),
        ));
    }
    Ok(Watch {
        _watcher: watcher,
        rx,
    })
}

fn under_roots(path: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|r| path.starts_with(r))
}

// ---- Enforcing backend (Linux / fanotify) --------------------------------

/// A file access that the enforcer **blocked** (denied) because it matched a
/// high-confidence (hash/YARA) detection.
#[derive(Debug, Clone)]
pub struct BlockedAccess {
    pub path: String,
    pub detections: Vec<crate::verdict::Detection>,
}

/// Events emitted by [`enforce`].
#[derive(Debug, Clone)]
pub enum EnforceEvent {
    /// Enforcement is live, watching `n` mount(s).
    Ready(usize),
    /// A malicious open/exec was denied.
    Blocked(BlockedAccess),
}

/// Run **blocking** on-access enforcement over `roots` until `stop` is set.
///
/// Each file open/exec under a watched root is scanned in-memory (read via the
/// kernel-supplied descriptor, so it never re-opens the file) and **denied** if
/// it matches a hash or YARA signature; everything else is allowed. Suspicious
/// heuristic/behavioural hits are *not* blocked (to avoid false-positive denial)
/// — they are surfaced by scans/monitoring instead.
///
/// Needs `CAP_SYS_ADMIN`; returns an error (which names the cause) otherwise.
#[cfg(target_os = "linux")]
pub fn enforce(
    engine: &crate::engine::Engine,
    roots: &[PathBuf],
    max_bytes: u64,
    stop: &std::sync::atomic::AtomicBool,
    mut on_event: impl FnMut(EnforceEvent),
) -> Result<()> {
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use nix::errno::Errno;
    use nix::sys::fanotify::{
        EventFFlags, Fanotify, FanotifyResponse, InitFlags, MarkFlags, MaskFlags, Response,
    };

    use crate::verdict::DetectionKind;

    let group = Fanotify::init(
        InitFlags::FAN_CLOEXEC | InitFlags::FAN_CLASS_CONTENT | InitFlags::FAN_NONBLOCK,
        EventFFlags::O_RDONLY | EventFFlags::O_LARGEFILE,
    )
    .map_err(|e| {
        ScanError::Update(format!(
            "fanotify init failed ({e}); real-time enforcement needs root / CAP_SYS_ADMIN"
        ))
    })?;

    let mask = MaskFlags::FAN_OPEN_PERM | MaskFlags::FAN_OPEN_EXEC_PERM;
    let mut marked = 0usize;
    for root in roots {
        if root.exists()
            && group
                .mark(
                    MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_MOUNT,
                    mask,
                    None,
                    Some(root),
                )
                .is_ok()
        {
            marked += 1;
        }
    }
    if marked == 0 {
        return Err(ScanError::Update(
            "real-time: no mountable paths to enforce".to_string(),
        ));
    }
    on_event(EnforceEvent::Ready(marked));

    let me = std::process::id() as i32;
    while !stop.load(Ordering::Relaxed) {
        let events = match group.read_events() {
            Ok(events) if !events.is_empty() => events,
            Ok(_) | Err(Errno::EAGAIN) => {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        for ev in events {
            let Some(fd) = ev.fd() else { continue };
            let mut blocked: Option<BlockedAccess> = None;

            // Never scan our own accesses (avoids self-recursion / deadlock).
            if ev.pid() != me {
                if let Some((path, bytes)) = read_event_file(&fd, roots, max_bytes) {
                    let hashes = crate::hashing::hash_bytes(&bytes);
                    if let Ok(dets) = engine.evaluate(&hashes, Some(&bytes)) {
                        let convicting: Vec<_> = dets
                            .into_iter()
                            .filter(|d| {
                                matches!(
                                    d.kind,
                                    DetectionKind::HashSignature | DetectionKind::YaraRule
                                )
                            })
                            .collect();
                        if !convicting.is_empty() {
                            blocked = Some(BlockedAccess {
                                path,
                                detections: convicting,
                            });
                        }
                    }
                }
            }

            let resp = if blocked.is_some() {
                Response::FAN_DENY
            } else {
                Response::FAN_ALLOW
            };
            let _ = group.write_response(FanotifyResponse::new(fd, resp));
            if let Some(b) = blocked {
                on_event(EnforceEvent::Blocked(b));
            }
        }
    }
    Ok(())
}

/// Resolve the accessed file's path and read its bytes **via the existing
/// descriptor** (positional reads, so the opening application's file offset is
/// untouched and no new open event is generated). Returns `None` to fail open
/// (allow) — e.g. outside the watched roots, empty, too large, or unreadable.
#[cfg(target_os = "linux")]
fn read_event_file(
    fd: &std::os::fd::BorrowedFd,
    roots: &[PathBuf],
    max_bytes: u64,
) -> Option<(String, Vec<u8>)> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::FileExt;

    let path = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).ok()?;
    if !under_roots(&path, roots) {
        return None;
    }
    let owned = fd.try_clone_to_owned().ok()?;
    let file = std::fs::File::from(owned);
    let len = file.metadata().ok()?.len();
    if len == 0 || len > max_bytes {
        return None;
    }
    let mut buf = vec![0u8; len as usize];
    let mut filled = 0usize;
    while filled < buf.len() {
        match file.read_at(&mut buf[filled..], filled as u64) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(_) => return None,
        }
    }
    buf.truncate(filled);
    Some((path.display().to_string(), buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_paths_is_error() {
        assert!(watch(&[]).is_err());
        assert!(watch(&[PathBuf::from("/nonexistent/talos/path/xyz")]).is_err());
    }

    #[test]
    fn detects_a_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let w = watch(&[dir.path().to_path_buf()]).unwrap();
        std::fs::write(dir.path().join("dropped.bin"), b"hello").unwrap();
        // Give the OS notifier a moment; this is generous to avoid flakiness.
        let got = w.rx.recv_timeout(std::time::Duration::from_secs(5));
        assert!(got.is_ok(), "expected a change event for the new file");
    }

    #[test]
    fn under_roots_matches_subpaths() {
        let roots = vec![PathBuf::from("/home/u/Downloads")];
        assert!(under_roots(Path::new("/home/u/Downloads/evil.exe"), &roots));
        assert!(!under_roots(Path::new("/etc/passwd"), &roots));
    }

    #[test]
    fn enforce_is_supported_only_on_linux() {
        assert_eq!(can_enforce(), cfg!(target_os = "linux"));
    }
}
