//! Local IPC transport.
//!
//! **Windows**: loopback TCP (`127.0.0.1`, ephemeral port). Named pipes created
//! by a service running as LocalSystem have a DACL that blocks non-elevated GUI
//! processes (even on admin accounts, UAC filtering removes the Administrators
//! SID from the token). TCP has no per-connection OS ACL, so any local process
//! can connect — the per-session auth token provides the access control.
//!
//! **Linux**: Unix-domain socket with `0600` permissions, so the token provides
//! defence in depth on top of the OS-level path access restriction.
//!
//! The agent writes the resolved endpoint (address string + token) to a
//! per-machine file so clients can discover it. On Windows the address string
//! is `"127.0.0.1:PORT"`; on Linux it is the socket-file path.

use std::io;

use serde::{Deserialize, Serialize};

/// How a client reaches the running agent: the platform endpoint **name**
/// (a `"127.0.0.1:PORT"` string on Windows, a socket-file path on Linux)
/// and the shared session token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointInfo {
    pub name: String,
    pub token: String,
}

// ── Windows: loopback TCP ────────────────────────────────────────────────────

#[cfg(windows)]
pub use std::net::TcpListener as Listener;
#[cfg(windows)]
pub use std::net::TcpStream as Stream;

/// Bind the agent's listener. Returns `(Listener, resolved_name)` where
/// `resolved_name` is the address to publish in the endpoint file.
#[cfg(windows)]
pub fn bind(_name: &str) -> io::Result<(Listener, String)> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?.to_string();
    Ok((listener, addr))
}

/// Accept one pending connection without blocking; `Ok(None)` = no pending conn.
#[cfg(windows)]
pub fn accept(listener: &Listener) -> io::Result<Option<Stream>> {
    match listener.accept() {
        Ok((stream, _)) => Ok(Some(stream)),
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

/// Connect to the agent's TCP endpoint.
#[cfg(windows)]
pub fn connect(addr: &str) -> io::Result<Stream> {
    std::net::TcpStream::connect(addr)
}

// ── Linux: Unix-domain socket ────────────────────────────────────────────────

#[cfg(not(windows))]
use interprocess::local_socket::GenericFilePath;
#[cfg(not(windows))]
use interprocess::local_socket::{prelude::*, ListenerNonblockingMode, ListenerOptions, Name};

#[cfg(not(windows))]
pub use interprocess::local_socket::{Listener, Stream};

#[cfg(not(windows))]
fn to_name(s: &str) -> io::Result<Name<'_>> {
    s.to_fs_name::<GenericFilePath>()
}

/// Bind a Unix-domain socket at `name`. Returns `(Listener, name.to_string())`.
#[cfg(not(windows))]
pub fn bind(name: &str) -> io::Result<(Listener, String)> {
    if let Some(parent) = std::path::Path::new(name).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(name);
    let listener = ListenerOptions::new()
        .name(to_name(name)?)
        .create_sync()?;
    listener.set_nonblocking(ListenerNonblockingMode::Accept)?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(name, std::fs::Permissions::from_mode(0o600));
    }
    Ok((listener, name.to_string()))
}

/// Accept one pending connection without blocking.
#[cfg(not(windows))]
pub fn accept(listener: &Listener) -> io::Result<Option<Stream>> {
    match listener.accept() {
        Ok(stream) => Ok(Some(stream)),
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

/// Connect to the agent's Unix socket.
#[cfg(not(windows))]
pub fn connect(name: &str) -> io::Result<Stream> {
    Stream::connect(to_name(name)?)
}
