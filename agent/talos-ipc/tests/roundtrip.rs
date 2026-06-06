//! End-to-end transport test: a real loopback TCP server and the client helper,
//! including the token check. Exercises the exact `std::net` path the Windows
//! build uses.

use std::thread;

use talos_ipc::client;
use talos_ipc::frame::{read_msg, write_msg};
use talos_ipc::proto::{Envelope, Request, Response};
use talos_ipc::transport::{bind_loopback, EndpointInfo};

/// Serve exactly one connection: validate the token and answer one request.
fn serve_one(listener: std::net::TcpListener, expected: String) {
    let (mut stream, _) = listener.accept().unwrap();
    let env: Envelope = read_msg(&mut stream).unwrap();
    let resp = if env.token != expected {
        Response::Error {
            message: "unauthorized".into(),
        }
    } else {
        match env.request {
            Request::Ping => Response::Pong {
                version: "test".into(),
                protocol: talos_ipc::PROTOCOL_VERSION,
            },
            _ => Response::Ack,
        }
    };
    write_msg(&mut stream, &resp).unwrap();
}

#[test]
fn authenticated_ping_gets_a_pong() {
    let (listener, port) = bind_loopback().unwrap();
    let token = "good-token".to_string();
    let server = thread::spawn({
        let token = token.clone();
        move || serve_one(listener, token)
    });

    let endpoint = EndpointInfo { port, token };
    let resp = client::call(&endpoint, Request::Ping).unwrap();
    assert!(matches!(resp, Response::Pong { .. }));
    server.join().unwrap();
}

#[test]
fn a_bad_token_is_rejected() {
    let (listener, port) = bind_loopback().unwrap();
    let server = thread::spawn(move || serve_one(listener, "good-token".into()));

    let endpoint = EndpointInfo {
        port,
        token: "WRONG".into(),
    };
    let resp = client::call(&endpoint, Request::Ping).unwrap();
    match resp {
        Response::Error { message } => assert_eq!(message, "unauthorized"),
        other => panic!("expected unauthorized error, got {other:?}"),
    }
    server.join().unwrap();
}
