//! Each builder setter reaches what it builds, `fill` takes the whole, the last write of a key wins,
//! and the settings are values a file fills.
#![cfg(all(feature = "websocket", feature = "webtransport"))]

use core::net::SocketAddr;
use core::time::Duration;

use coqui_builder::builder::BuildError;
use coqui_builder::{NonDefault, Partial};
use coqui_transport_web::{Failure, Limits, websocket, webtransport};

fn loopback() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

/// What a non-default says, as `(setting, value, default)` texts.
fn lines(found: &[NonDefault]) -> Vec<(String, String, String)> {
    found
        .iter()
        .map(|item| {
            (
                item.setting.clone(),
                item.value.to_string(),
                item.default.to_string(),
            )
        })
        .collect()
}

#[test]
fn the_defaults_report_nothing() {
    assert!(
        websocket::Dialer::builder()
            .build()
            .unwrap()
            .non_defaults()
            .is_empty()
    );
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .build()
        .unwrap();
    assert!(listener.non_defaults().is_empty());
    assert!(!listener.plain_beyond_loopback());
}

#[test]
fn every_dialer_setter_reaches_the_settings() {
    let mut limits = Limits::default();
    limits.max_message = 1234;
    let dialer = websocket::Dialer::builder()
        .frames(websocket::Frames::Binary)
        .datagrams(true)
        .limits(limits)
        .plain_beyond_loopback(true)
        .local_addr(loopback())
        .headers(vec![("x-token".to_owned(), "secret".to_owned())])
        .build()
        .unwrap();
    let settings = dialer.settings();
    assert_eq!(settings.frames, websocket::Frames::Binary);
    assert!(settings.datagrams);
    assert_eq!(settings.limits.max_message, 1234);
    assert!(settings.plain_beyond_loopback);
    assert_eq!(settings.local_addr, Some(loopback()));
    let found: Vec<String> = dialer
        .non_defaults()
        .into_iter()
        .map(|setting| setting.setting)
        .collect();
    assert_eq!(
        found,
        [
            "datagrams",
            "frames",
            "limits.max_message",
            "local_addr",
            "plain_beyond_loopback"
        ]
    );
    assert!(!format!("{dialer:?}").contains("secret"));
}

#[test]
fn a_dialer_takes_its_settings_whole_and_the_last_write_wins() {
    let mut whole = websocket::DialerSettings::default();
    whole.datagrams = true;
    let dialer = websocket::Dialer::builder()
        .plain_beyond_loopback(true)
        .fill(Partial::from(whole))
        .frames(websocket::Frames::Binary)
        .build()
        .unwrap();
    let settings = dialer.settings();
    assert!(settings.datagrams);
    assert!(
        !settings.plain_beyond_loopback,
        "fill replaced the earlier flag"
    );
    assert_eq!(settings.frames, websocket::Frames::Binary);
}

#[test]
fn a_plain_listener_beyond_loopback_is_a_refused_choice_and_then_a_listed_one() {
    let wide = SocketAddr::from(([0, 0, 0, 0], 0));
    assert!(matches!(
        websocket::Listener::builder(wide, websocket::ServerTls::Plain).build(),
        Err(BuildError::Failed(Failure::Permission))
    ));
    let listener = websocket::Listener::builder(wide, websocket::ServerTls::Plain)
        .plain_beyond_loopback(true)
        .build()
        .unwrap();
    assert!(listener.plain_beyond_loopback());
    assert_eq!(
        lines(&listener.non_defaults()),
        [(
            "plain_beyond_loopback".to_owned(),
            "bool(true)".to_owned(),
            "bool(false)".to_owned()
        )]
    );
}

#[test]
fn a_listener_without_its_address_or_tls_names_what_is_missing() {
    let error = websocket::ListenerBuilder::new().build().unwrap_err();
    let text = error.to_string();
    assert!(text.contains("address") && text.contains("tls"), "{text}");
    let error = webtransport::ListenerBuilder::new().build().unwrap_err();
    let text = error.to_string();
    assert!(text.contains("binding") && text.contains("tls"), "{text}");
    let error = webtransport::DialerBuilder::new().build().unwrap_err();
    assert!(error.to_string().contains("trust"));
}

#[test]
fn every_listener_setter_reaches_the_settings() {
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .frames(websocket::Frames::Binary)
        .origins(["https://app.example".to_owned()])
        .admission(|_| true)
        .build()
        .unwrap();
    let settings = listener.settings();
    assert_eq!(settings.frames, websocket::Frames::Binary);
    assert_eq!(settings.origins, ["https://app.example"]);
    let names: Vec<String> = listener
        .non_defaults()
        .into_iter()
        .map(|setting| setting.setting)
        .collect();
    assert_eq!(names, ["frames", "origins"]);
}

#[test]
fn limits_and_signalling_are_values_a_file_fills() {
    let limits = toml::from_str::<Partial<Limits>>("max_message = 7\nidle = 2\n")
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(limits.max_message, 7);
    assert_eq!(limits.idle, Duration::from_secs(2));
    assert_eq!(limits.pending, Limits::default().pending);
    assert_eq!(
        toml::from_str::<Partial<Limits>>("")
            .unwrap()
            .build()
            .unwrap(),
        Limits::default()
    );
    let units = toml::from_str::<Partial<Limits>>("handshake = \"250ms\"\nsend = \"1.5h\"")
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(units.handshake, Duration::from_millis(250));
    assert_eq!(units.send, Duration::from_secs(5400));

    let dialer = toml::from_str::<Partial<websocket::DialerSettings>>(
        "frames = \"binary\"\nlocal_addr = \"127.0.0.1:0\"\n[limits]\nmax_message = 7\n",
    )
    .unwrap()
    .build()
    .unwrap();
    assert_eq!(dialer.frames, websocket::Frames::Binary);
    assert_eq!(dialer.local_addr, Some(loopback()));
    assert_eq!(dialer.limits.max_message, 7);
    let json = serde_json::from_str::<Partial<websocket::DialerSettings>>(
        r#"{"datagrams": true, "limits": {"pending": 3}}"#,
    )
    .unwrap()
    .build()
    .unwrap();
    assert!(json.datagrams);
    assert_eq!(json.limits.pending, 3);

    let listener = toml::from_str::<Partial<websocket::ListenerSettings>>(
        "origins = [\"https://a.example\", \"https://b.example\"]",
    )
    .unwrap()
    .build()
    .unwrap();
    assert_eq!(listener.origins, ["https://a.example", "https://b.example"]);
}

#[test]
fn settings_refuse_unknown_keys() {
    let refused = |text: &str| toml::from_str::<Partial<Limits>>(text).is_err();
    assert!(refused("max_mesage = 1"));
    assert!(toml::from_str::<Partial<websocket::DialerSettings>>("tls = true").is_err());
    assert!(toml::from_str::<Partial<websocket::ListenerSettings>>("frames = \"ascii\"").is_err());
    assert!(toml::from_str::<Partial<webtransport::DialerSettings>>("limits = 3").is_err());
}

#[test]
fn webtransport_settings_are_read_and_the_builders_report_them() {
    let settings = toml::from_str::<Partial<webtransport::ListenerSettings>>(
        "origins = [\"https://a.example\"]\n[limits]\npending = 3\n",
    )
    .unwrap()
    .build()
    .unwrap();
    assert_eq!(settings.origins, ["https://a.example"]);
    assert_eq!(settings.limits.pending, 3);
    let dialer =
        toml::from_str::<Partial<webtransport::DialerSettings>>("local_addr = \"127.0.0.1:0\"")
            .unwrap()
            .build()
            .unwrap();
    assert_eq!(dialer.local_addr, Some(loopback()));
}
