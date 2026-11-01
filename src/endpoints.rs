//! Where one expected peer can be reached. Locations, not evidence of identity.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use url::{Host, Url};

/// The SHA-256 of a certificate a WebTransport client pins, written `sha256:<64 hex digits>`.
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct CertificatePin([u8; 32]);

impl CertificatePin {
    /// A pin of the given digest.
    #[must_use]
    pub const fn from_bytes(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// The digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for CertificatePin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sha256:")?;
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl fmt::Debug for CertificatePin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CertificatePin({self})")
    }
}

impl FromStr for CertificatePin {
    type Err = EndpointError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let hex = text.strip_prefix("sha256:").ok_or(EndpointError::Pin)?;
        if hex.len() != 64 || !hex.is_ascii() {
            return Err(EndpointError::Pin);
        }
        let mut digest = [0_u8; 32];
        for (slot, pair) in digest.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
            let pair = core::str::from_utf8(pair).map_err(|_| EndpointError::Pin)?;
            *slot = u8::from_str_radix(pair, 16).map_err(|_| EndpointError::Pin)?;
        }
        Ok(Self(digest))
    }
}

/// Why a set of endpoints was refused. It never quotes the input: a URL can hold a secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EndpointError {
    /// Neither endpoint was given.
    Empty,
    /// A URL did not parse.
    Url,
    /// The WebTransport URL is not `https://` with an explicit port.
    WebTransport,
    /// The WebSocket URL is neither `wss://` nor an explicitly allowed loopback `ws://`.
    WebSocket,
    /// A URL holds credentials, a query or a fragment.
    NotPlain,
    /// The two endpoints name different hosts.
    HostMismatch,
    /// A pin is not `sha256:<64 hex digits>`, or was given with no WebTransport endpoint.
    Pin,
}

impl fmt::Display for EndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "at least one endpoint is required",
            Self::Url => "an endpoint is not a valid url",
            Self::WebTransport => "a webtransport endpoint must be https with an explicit port",
            Self::WebSocket => "a websocket endpoint must be wss, or ws on loopback when allowed",
            Self::NotPlain => "an endpoint url must hold no credentials, query or fragment",
            Self::HostMismatch => "webtransport and websocket endpoints must share a host",
            Self::Pin => "a certificate pin must be sha256 hex and needs a webtransport endpoint",
        })
    }
}

impl core::error::Error for EndpointError {}

/// Explicit endpoints for one expected peer. A WebSocket endpoint is never derived from a
/// WebTransport URL, and both must prove the same peer after they connect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoints {
    webtransport: Option<Url>,
    websocket: Option<Url>,
    certificate_pins: Vec<CertificatePin>,
}

impl Endpoints {
    /// Starts an empty set.
    pub fn builder() -> EndpointsBuilder {
        EndpointsBuilder::default()
    }

    /// The WebTransport endpoint.
    #[must_use]
    pub const fn webtransport(&self) -> Option<&Url> {
        self.webtransport.as_ref()
    }

    /// The WebSocket endpoint.
    #[must_use]
    pub const fn websocket(&self) -> Option<&Url> {
        self.websocket.as_ref()
    }

    /// The WebTransport certificates to pin. When any is set, no failure falls back.
    #[must_use]
    pub fn certificate_pins(&self) -> &[CertificatePin] {
        &self.certificate_pins
    }
}

/// Builds [`Endpoints`]; all validation happens in [`build`](Self::build).
#[derive(Clone, Debug, Default)]
#[must_use]
pub struct EndpointsBuilder {
    webtransport: Option<String>,
    websocket: Option<String>,
    certificate_pins: Vec<CertificatePin>,
    allow_plain_loopback: bool,
}

impl EndpointsBuilder {
    /// The `https://host:port/path` a WebTransport session opens.
    pub fn webtransport(mut self, url: impl AsRef<str>) -> Self {
        self.webtransport = Some(url.as_ref().to_string());
        self
    }

    /// The `wss://` URL of the WebSocket endpoint.
    pub fn websocket(mut self, url: impl AsRef<str>) -> Self {
        self.websocket = Some(url.as_ref().to_string());
        self
    }

    /// Pins a WebTransport server certificate. Pins are additive.
    pub fn certificate_pin(mut self, pin: CertificatePin) -> Self {
        self.certificate_pins.push(pin);
        self
    }

    /// Allows `ws://` on a loopback address, for local development. Encrypted transport stays
    /// required for every other address.
    pub fn allow_plain_loopback(mut self, allow: bool) -> Self {
        self.allow_plain_loopback = allow;
        self
    }

    /// Validates the set.
    ///
    /// # Errors
    ///
    /// [`EndpointError`] naming the first rule broken.
    pub fn build(self) -> Result<Endpoints, EndpointError> {
        let webtransport = self.webtransport.as_deref().map(parse).transpose()?;
        let websocket = self.websocket.as_deref().map(parse).transpose()?;
        if webtransport.is_none() && websocket.is_none() {
            return Err(EndpointError::Empty);
        }
        if let Some(url) = &webtransport
            && (url.scheme() != "https" || url.port().is_none())
        {
            return Err(EndpointError::WebTransport);
        }
        if let Some(url) = &websocket {
            let plain_allowed = self.allow_plain_loopback && is_loopback(url);
            if url.scheme() != "wss" && !(url.scheme() == "ws" && plain_allowed) {
                return Err(EndpointError::WebSocket);
            }
        }
        if let (Some(first), Some(second)) = (&webtransport, &websocket)
            && first.host() != second.host()
        {
            return Err(EndpointError::HostMismatch);
        }
        if !self.certificate_pins.is_empty() && webtransport.is_none() {
            return Err(EndpointError::Pin);
        }
        Ok(Endpoints {
            webtransport,
            websocket,
            certificate_pins: self.certificate_pins,
        })
    }
}

fn parse(text: &str) -> Result<Url, EndpointError> {
    let url = Url::parse(text).map_err(|_| EndpointError::Url)?;
    if url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(EndpointError::NotPlain);
    }
    Ok(url)
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WT: &str = "https://agent.example:4433/acp";
    const WS: &str = "wss://agent.example:4434/acp";

    fn refused(builder: EndpointsBuilder, why: EndpointError) {
        assert_eq!(builder.build().unwrap_err(), why);
    }

    #[test]
    fn explicit_secure_endpoints_are_accepted() {
        let both = Endpoints::builder()
            .webtransport(WT)
            .websocket(WS)
            .build()
            .unwrap();
        assert_eq!(both.webtransport().unwrap().as_str(), WT);
        assert_eq!(both.websocket().unwrap().as_str(), WS);
    }

    #[test]
    fn no_endpoint_is_refused() {
        refused(Endpoints::builder(), EndpointError::Empty);
    }

    #[test]
    fn webtransport_needs_https_and_an_explicit_port() {
        refused(
            Endpoints::builder().webtransport("https://agent.example/acp"),
            EndpointError::WebTransport,
        );
        refused(
            Endpoints::builder().webtransport("http://agent.example:80/"),
            EndpointError::WebTransport,
        );
    }

    #[test]
    fn plain_websocket_is_only_for_an_allowed_loopback() {
        refused(
            Endpoints::builder().websocket("ws://agent.example/acp"),
            EndpointError::WebSocket,
        );
        refused(
            Endpoints::builder().websocket("ws://localhost:8080/acp"),
            EndpointError::WebSocket,
        );
        refused(
            Endpoints::builder()
                .websocket("ws://agent.example/")
                .allow_plain_loopback(true),
            EndpointError::WebSocket,
        );
        for url in [
            "ws://localhost:8080/acp",
            "ws://127.0.0.1:8080/",
            "ws://[::1]:8080/",
        ] {
            assert!(
                Endpoints::builder()
                    .websocket(url)
                    .allow_plain_loopback(true)
                    .build()
                    .is_ok(),
                "{url}"
            );
        }
    }

    #[test]
    fn endpoints_share_a_host() {
        refused(
            Endpoints::builder()
                .webtransport(WT)
                .websocket("wss://else.example/"),
            EndpointError::HostMismatch,
        );
        assert!(
            Endpoints::builder()
                .webtransport("https://AGENT.example:4433/")
                .websocket(WS)
                .build()
                .is_ok()
        );
    }

    #[test]
    fn a_url_holds_no_credentials_query_or_fragment() {
        for url in [
            "wss://agent.example/?key=x",
            "wss://user:pw@agent.example/",
            "wss://agent.example/#x",
        ] {
            refused(Endpoints::builder().websocket(url), EndpointError::NotPlain);
        }
    }

    #[test]
    fn an_error_never_quotes_the_url() {
        let error = Endpoints::builder()
            .websocket("wss://agent.example/?key=secret")
            .build()
            .unwrap_err();
        assert!(!error.to_string().contains("secret"));
    }

    #[test]
    fn a_pin_round_trips_and_a_malformed_one_is_refused() {
        let text = alloc::format!("sha256:{}", "ab".repeat(32));
        let pin: CertificatePin = text.parse().unwrap();
        assert_eq!(pin.to_string(), text);
        assert_eq!(pin, CertificatePin::from_bytes([0xab; 32]));
        for bad in ["ab", "sha256:ab", "md5:00", "sha256:zz"] {
            assert_eq!(bad.parse::<CertificatePin>(), Err(EndpointError::Pin));
        }
        let long = alloc::format!("sha256:{}", "é".repeat(32));
        assert_eq!(long.parse::<CertificatePin>(), Err(EndpointError::Pin));
    }

    #[test]
    fn a_pin_needs_a_webtransport_endpoint() {
        refused(
            Endpoints::builder()
                .websocket(WS)
                .certificate_pin(CertificatePin::from_bytes([1; 32])),
            EndpointError::Pin,
        );
    }
}
