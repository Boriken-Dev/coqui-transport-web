//! An echo peer on loopback for interoperability tests: prints its ports and certificate pin as one JSON line, then echoes
//! every message on both a WebSocket and a WebTransport listener until killed, and every WebTransport datagram.
//!
//! `cargo run --all-features --example echo`

#![allow(clippy::std_instead_of_core, clippy::std_instead_of_alloc)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;

use coqui_web_channel::websocket;
use coqui_web_channel::{CertificatePin, Channel, webtransport};
use rustls::pki_types::PrivatePkcs8KeyDer;

fn echo<C: Channel>(channel: &C) {
    thread::scope(|scope| {
        if let Some(datagrams) = channel.datagrams() {
            scope.spawn(move || {
                while let Ok(Some(datagram)) = datagrams.receive(None) {
                    let _ = datagrams.send(&datagram);
                }
            });
        }
        while let Ok(Some(message)) = channel.receive(None) {
            if channel.send(&message).is_err() {
                break;
            }
        }
        channel.close();
    });
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let loopback: SocketAddr = "127.0.0.1:0".parse()?;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_owned()])?;
    // What a browser's serverCertificateHashes requires: at most 14 days.
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    params.not_after = params.not_before + time::Duration::days(10);
    let certificate = params.self_signed(&key)?;
    let der = certificate.der().clone();
    let tls = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![der.clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )?,
    );
    let hash = wtransport::tls::Certificate::from_der(der.to_vec())?.hash();
    let pin = CertificatePin::from_bytes(*hash.as_ref());

    let plain = websocket::Listener::bind(loopback, None)?;
    let quic = webtransport::Listener::bind(loopback, tls)?;
    println!(
        "{{\"websocket\":{},\"webtransport\":{},\"pin\":\"{pin}\"}}",
        plain.local_addr()?.port(),
        quic.local_addr().port()
    );
    thread::spawn(move || {
        while let Ok(channel) = plain.accept(None) {
            thread::spawn(move || echo(&channel));
        }
    });
    while let Ok(channel) = quic.accept(None) {
        thread::spawn(move || echo(&channel));
    }
    Ok(())
}
