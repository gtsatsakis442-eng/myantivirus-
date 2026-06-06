//! Client side: one-shot authenticated request/response calls to the agent.

use std::io;

use crate::frame::{read_msg, write_msg};
use crate::proto::{Envelope, Request, Response};
use crate::transport::{connect_loopback, EndpointInfo};

/// Connect to the agent, send a single authenticated `request`, and read the
/// one `Response`. The connection is closed when this returns.
pub fn call(endpoint: &EndpointInfo, request: Request) -> io::Result<Response> {
    let mut stream = connect_loopback(endpoint.port)?;
    let envelope = Envelope {
        token: endpoint.token.clone(),
        request,
    };
    write_msg(&mut stream, &envelope)?;
    read_msg(&mut stream)
}
