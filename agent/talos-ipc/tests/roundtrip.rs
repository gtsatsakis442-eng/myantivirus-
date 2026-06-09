//! End-to-end transport test over a real local socket (a Unix socket on Linux),
//! including the token check — the same `interprocess` path the Windows named
//! pipe uses.

use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use talos_ipc::client;
use talos_ipc::frame::{read_msg, write_msg};
use talos_ipc::proto::{Envelope, Request, Response};
use talos_ipc::transport::{accept, bind, EndpointInfo};
use talos_ipc::Listener;

fn temp_name() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir()
        .join(format!(
            "talos-ipc-test-{}-{nanos}.sock",
            std::process::id()
        ))
        .to_string_lossy()
        .into_owned()
}

/// Serve exactly one connection: validate the token and answer one request.
fn serve_one(listener: Listener, expected: String) {
    for _ in 0..500 {
        match accept(&listener).unwrap() {
            Some(mut stream) => {
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
                return;
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    }
    panic!("no connection accepted in time");
}

#[test]
fn authenticated_ping_gets_a_pong() {
    let name = temp_name();
    let listener = bind(&name).unwrap();
    let token = "good-token".to_string();
    let server = thread::spawn({
        let token = token.clone();
        move || serve_one(listener, token)
    });
    thread::sleep(Duration::from_millis(50));

    let endpoint = EndpointInfo { name, token };
    let resp = client::call(&endpoint, Request::Ping).unwrap();
    assert!(matches!(resp, Response::Pong { .. }));
    server.join().unwrap();
}

#[test]
fn a_bad_token_is_rejected() {
    let name = temp_name();
    let listener = bind(&name).unwrap();
    let server = thread::spawn(move || serve_one(listener, "good-token".into()));
    thread::sleep(Duration::from_millis(50));

    let endpoint = EndpointInfo {
        name,
        token: "WRONG".into(),
    };
    let resp = client::call(&endpoint, Request::Ping).unwrap();
    match resp {
        Response::Error { message } => assert_eq!(message, "unauthorized"),
        other => panic!("expected unauthorized error, got {other:?}"),
    }
    server.join().unwrap();
}
