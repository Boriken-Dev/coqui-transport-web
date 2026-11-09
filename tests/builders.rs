//! Each builder setter reaches what it builds, `settings` takes the whole, the last setter wins,
//! and the settings are values a file fills.
#![cfg(all(feature = "websocket", feature = "webtransport"))]

use core::net::SocketAddr;
use core::time::Duration;

use coqui_transport_web::{Limits, NonDefault, websocket, webtransport};
use guatiao_serde::Presentation;
use guatiao_serde::text::{json, toml};

fn plain() -> Presentation {
    Presentation::new()
}

fn loopback() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

#[test]
fn the_defaults_report_nothing() {
    assert!(
        websocket::Dialer::builder()
            .build()
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
        .header("x-token", "secret")
        .build();
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
fn a_dialer_takes_its_settings_whole_and_the_last_setter_wins() {
    let mut whole = websocket::DialerSettings::default();
    whole.datagrams = true;
    let dialer = websocket::Dialer::builder()
        .plain_beyond_loopback(true)
        .settings(whole)
        .frames(websocket::Frames::Binary)
        .build();
    let settings = dialer.settings();
    assert!(settings.datagrams);
    assert!(
        !settings.plain_beyond_loopback,
        "settings replaced the earlier flag"
    );
    assert_eq!(settings.frames, websocket::Frames::Binary);
}

#[test]
fn a_plain_listener_beyond_loopback_is_a_refused_choice_and_then_a_listed_one() {
    let wide = SocketAddr::from(([0, 0, 0, 0], 0));
    assert!(matches!(
        websocket::Listener::builder(wide, websocket::ServerTls::Plain).build(),
        Err(coqui_transport_web::Failure::Permission)
    ));
    let listener = websocket::Listener::builder(wide, websocket::ServerTls::Plain)
        .plain_beyond_loopback(true)
        .build()
        .unwrap();
    assert!(listener.plain_beyond_loopback());
    assert_eq!(
        listener.non_defaults(),
        [NonDefault::new("plain_beyond_loopback", "true", "false")]
    );
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
    let limits: Limits = toml::from_str_as("max_message = 7\nidle = 2\n", plain()).unwrap();
    assert_eq!(limits.max_message, 7);
    assert_eq!(limits.idle, Duration::from_secs(2));
    assert_eq!(limits.pending, Limits::default().pending);
    assert_eq!(
        toml::from_str_as::<Limits>("", plain()).unwrap(),
        Limits::default()
    );
    let text = toml::to_string_of(&limits, plain()).unwrap();
    assert_eq!(toml::from_str_as::<Limits>(&text, plain()).unwrap(), limits);

    let mut dialer = websocket::DialerSettings::default();
    dialer.frames = websocket::Frames::Binary;
    dialer.limits = limits;
    dialer.local_addr = Some(loopback());
    let text = json::to_string_pretty_of(&dialer, plain()).unwrap();
    assert_eq!(
        json::from_str_as::<websocket::DialerSettings>(&text, plain()).unwrap(),
        dialer
    );
    let mut listener = websocket::ListenerSettings::default();
    listener.origins = vec!["https://a.example".to_owned()];
    let text = toml::to_string_of(&listener, plain()).unwrap();
    assert_eq!(
        toml::from_str_as::<websocket::ListenerSettings>(&text, plain()).unwrap(),
        listener
    );
}

#[test]
fn settings_refuse_unknown_keys() {
    assert!(toml::from_str_as::<Limits>("max_mesage = 1", plain()).is_err());
    assert!(toml::from_str_as::<websocket::DialerSettings>("tls = true", plain()).is_err());
    assert!(
        toml::from_str_as::<websocket::ListenerSettings>("frames = \"ascii\"", plain()).is_err()
    );
    assert!(toml::from_str_as::<webtransport::DialerSettings>("limits = 3", plain()).is_err());
}

#[test]
fn webtransport_settings_round_trip_and_the_builders_report_them() {
    let mut settings = webtransport::ListenerSettings::default();
    settings.origins = vec!["https://a.example".to_owned()];
    settings.limits.pending = 3;
    let text = toml::to_string_of(&settings, plain()).unwrap();
    assert_eq!(
        toml::from_str_as::<webtransport::ListenerSettings>(&text, plain()).unwrap(),
        settings
    );
    let mut dialer = webtransport::DialerSettings::default();
    dialer.local_addr = Some(loopback());
    let text = json::to_string_pretty_of(&dialer, plain()).unwrap();
    assert_eq!(
        json::from_str_as::<webtransport::DialerSettings>(&text, plain()).unwrap(),
        dialer
    );
}
