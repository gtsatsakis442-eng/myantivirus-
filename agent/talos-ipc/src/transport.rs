//! Loopback-TCP transport: bind/connect helpers plus the [`EndpointInfo`] a
//! client needs to reach the agent (port + token).

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};

use serde::{Deserialize, Serialize};

/// How a client reaches the running agent: a loopback TCP port and the shared
/// secret token. The agent writes this (as JSON, private permissions) on
/// startup; clients read it back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointInfo {
    pub port: u16,
    pub token: String,
}

/// Bind the agent's IPC listener on `127.0.0.1` with an OS-assigned port.
/// Returns the listener and the port that was chosen.
pub fn bind_loopback() -> io::Result<(TcpListener, u16)> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    Ok((listener, port))
}

/// Connect to the agent on `127.0.0.1:port`.
pub fn connect_loopback(port: u16) -> io::Result<TcpStream> {
    TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
}
