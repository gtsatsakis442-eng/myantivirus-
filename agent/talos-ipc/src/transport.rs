//! Local-socket transport: a **named pipe** (Windows) / **Unix-domain socket**
//! (Linux) rather than loopback TCP, so the agent's control channel is not
//! reachable over the network and is gated by OS access control — the socket
//! file's `0600` mode on Linux, the pipe's SYSTEM/Administrators DACL on
//! Windows. A per-session token is still required as defense in depth.
//!
//! The Linux path uses real Unix sockets, so the whole transport is testable
//! off-Windows; the Windows named-pipe path uses the identical `interprocess`
//! API and is validated by the Windows CI job.

use std::io;

#[cfg(not(windows))]
use interprocess::local_socket::GenericFilePath;
#[cfg(windows)]
use interprocess::local_socket::GenericNamespaced;
use interprocess::local_socket::{prelude::*, ListenerNonblockingMode, ListenerOptions, Name};
use serde::{Deserialize, Serialize};

/// The concrete `interprocess` local-socket types, re-exported so dependents
/// don't need a direct `interprocess` dependency.
pub use interprocess::local_socket::{Listener, Stream};

/// How a client reaches the running agent: the platform socket **name** (a pipe
/// name on Windows, a socket-file path on Linux) and the shared secret token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointInfo {
    pub name: String,
    pub token: String,
}

/// Build a platform socket name: a namespaced pipe name on Windows, a
/// filesystem socket path on Linux (so we can `chmod 0600` it).
#[cfg(windows)]
fn to_name(s: &str) -> io::Result<Name<'_>> {
    s.to_ns_name::<GenericNamespaced>()
}

#[cfg(not(windows))]
fn to_name(s: &str) -> io::Result<Name<'_>> {
    s.to_fs_name::<GenericFilePath>()
}

/// Bind the agent's listener at `name` with **non-blocking accept** (so the
/// serve loop can poll a stop flag); accepted streams stay blocking. On Linux a
/// stale socket file is removed first and the new one is restricted to `0600`.
pub fn bind(name: &str) -> io::Result<Listener> {
    #[cfg(unix)]
    {
        // The socket file's parent dir must exist; clear any corpse socket.
        if let Some(parent) = std::path::Path::new(name).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::remove_file(name);
    }
    let listener = ListenerOptions::new().name(to_name(name)?).create_sync()?;
    listener.set_nonblocking(ListenerNonblockingMode::Accept)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(name, std::fs::Permissions::from_mode(0o600));
    }
    Ok(listener)
}

/// Accept one pending connection without blocking. `Ok(None)` means no
/// connection is pending right now (would-block) — the caller should poll again.
pub fn accept(listener: &Listener) -> io::Result<Option<Stream>> {
    match listener.accept() {
        Ok(stream) => Ok(Some(stream)),
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

/// Connect to the agent's socket `name`.
pub fn connect(name: &str) -> io::Result<Stream> {
    Stream::connect(to_name(name)?)
}
