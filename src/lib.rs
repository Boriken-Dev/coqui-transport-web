#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

mod channel;
mod endpoints;
mod failure;
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

pub use channel::{
    Channel, Datagrams, Delivery, Dialer, Kind, NoPreflight, Preflight, Unverified, connect,
};
pub use endpoints::{CertificatePin, EndpointError, Endpoints, EndpointsBuilder};
pub use failure::{Failure, Phase, Recovery};
#[cfg(any(feature = "websocket", feature = "webtransport"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "websocket", feature = "webtransport"))))]
pub use pump::{Cancel, Limits};
