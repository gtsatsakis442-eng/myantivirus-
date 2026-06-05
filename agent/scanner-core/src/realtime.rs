//! Real-time on-access monitoring (**user-mode**).
//!
//! Watches folders and reports files as they are created or modified, so the
//! agent can **auto-scan them on access**. This is the user-mode form of
//! on-access protection — a real, useful first step toward the roadmap's
//! real-time module. True *pre-execution blocking* needs a kernel file-system
//! **minifilter** and remains Phase 2 (see docs/01); this layer detects and
//! reports after a file lands, it does not block the I/O.

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};

use notify::{EventKind, RecursiveMode, Watcher as _};

use crate::error::{Result, ScanError};

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
}
