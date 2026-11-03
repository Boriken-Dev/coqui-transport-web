//! What this side lets through of a peer's session description.

use core::net::{IpAddr, SocketAddr};

fn is_candidate(line: &str) -> bool {
    line.starts_with("a=candidate:") || line == "a=end-of-candidates"
}

fn joined<'a>(lines: impl Iterator<Item = &'a str>) -> String {
    let mut out = String::new();
    for line in lines {
        out.push_str(line);
        out.push_str("\r\n");
    }
    out
}

/// An offer with its candidates gone, or `None` if it asks for anything but a data channel. An ICE-lite answerer never sends a check,
/// and answers a check where it came from, so a candidate naming someone else has nothing to act on and is not kept.
pub(super) fn offer(sdp: &str) -> Option<String> {
    let mut sections = 0_usize;
    for line in sdp.lines() {
        if line.starts_with("m=") {
            sections += 1;
            if !line.starts_with("m=application ") {
                return None;
            }
        }
    }
    (sections == 1).then(|| joined(sdp.lines().filter(|line| !is_candidate(line))))
}

/// The address of `a=candidate:` line if it is a UDP host candidate.
fn host_candidate(line: &str) -> Option<SocketAddr> {
    let mut fields = line.strip_prefix("a=candidate:")?.split_ascii_whitespace();
    let transport = fields.nth(2)?;
    let _priority = fields.next()?;
    let address: IpAddr = fields.next()?.parse().ok()?;
    let port: u16 = fields.next()?.parse().ok()?;
    let host = transport.eq_ignore_ascii_case("udp")
        && fields.next()? == "typ"
        && fields.next()? == "host";
    host.then(|| SocketAddr::new(address, port))
}

/// An answer with its one candidate, or `None` unless it has exactly one, of the host kind over UDP, and at `peer` unless `any` allows
/// another address. A peer gets to name one place for this side's checks to go, and only where it already is.
pub(super) fn answer(sdp: &str, peer: IpAddr, any: bool) -> Option<(String, SocketAddr)> {
    let mut lines = sdp.lines().filter(|line| line.starts_with("a=candidate:"));
    let only = lines.next()?;
    if lines.next().is_some() {
        return None;
    }
    let candidate = host_candidate(only)?;
    (any || candidate.ip().to_canonical() == peer.to_canonical())
        .then(|| (joined(sdp.lines()), candidate))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "a=candidate:1 1 udp 2130706431 192.0.2.7 4433 typ host";

    fn peer() -> IpAddr {
        "192.0.2.7".parse().unwrap()
    }

    #[test]
    fn an_offer_keeps_nothing_about_candidates() {
        let kept = offer(&format!(
            "v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n{HOST}\r\na=end-of-candidates\r\na=setup:actpass\r\n"
        ))
        .unwrap();
        assert!(!kept.contains("candidate"), "{kept}");
        assert!(kept.contains("a=setup:actpass"));
    }

    #[test]
    fn an_offer_of_anything_but_one_data_channel_is_refused() {
        assert_eq!(offer("v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"), None);
        assert_eq!(offer("v=0\r\n"), None);
        assert_eq!(
            offer(
                "v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\n"
            ),
            None
        );
    }

    #[test]
    fn an_answer_has_one_host_candidate_where_the_peer_is() {
        let sdp = format!("v=0\r\n{HOST}\r\n");
        let (_, candidate) = answer(&sdp, peer(), false).unwrap();
        assert_eq!(candidate, "192.0.2.7:4433".parse().unwrap());
    }

    #[test]
    fn an_answer_lying_about_where_it_is_refused_unless_allowed() {
        let sdp = format!("v=0\r\n{HOST}\r\n");
        let other: IpAddr = "198.51.100.1".parse().unwrap();
        assert!(answer(&sdp, other, false).is_none());
        assert!(answer(&sdp, other, true).is_some());
    }

    #[test]
    fn an_answer_with_no_host_candidate_or_several_is_refused() {
        assert!(answer("v=0\r\n", peer(), true).is_none());
        let two = format!("v=0\r\n{HOST}\r\n{HOST}\r\n");
        assert!(answer(&two, peer(), true).is_none());
        for line in [
            "a=candidate:1 1 tcp 2130706431 192.0.2.7 4433 typ host",
            "a=candidate:1 1 udp 2130706431 192.0.2.7 4433 typ relay",
            "a=candidate:1 1 udp 2130706431 x.local 4433 typ host",
            "a=candidate:1 1 udp",
        ] {
            assert!(answer(&format!("v=0\r\n{line}\r\n"), peer(), true).is_none());
        }
    }
}
