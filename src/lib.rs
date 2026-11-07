#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

mod endpoint;
mod fallback;
pub mod frame;
#[cfg(any(feature = "websocket", feature = "webtransport"))]
mod pump;
#[cfg(feature = "webrtc")]
#[cfg_attr(docsrs, doc(cfg(feature = "webrtc")))]
pub mod webrtc;
#[cfg(feature = "websocket")]
#[cfg_attr(docsrs, doc(cfg(feature = "websocket")))]
pub mod websocket;
#[cfg(feature = "webtransport")]
#[cfg_attr(docsrs, doc(cfg(feature = "webtransport")))]
pub mod webtransport;

pub use coqui_transport::{Capabilities, Carrier, Channel, Datagrams, Delivery, Failure};
pub use endpoint::{CertificatePin, EndpointError, Endpoints, EndpointsBuilder};
pub use fallback::{
    Dialer, FailureExt, Kind, NoPreflight, Phase, Preflight, Recovery, Unverified, connect,
};
#[cfg(any(feature = "websocket", feature = "webtransport"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "websocket", feature = "webtransport"))))]
pub use pump::{Cancel, Limits};
