//! What Kiri's daemon.json says about registries, with Docker's meaning for
//! each key:
//!
//! - `insecure-registries`: hosts (`registry.lan:5000`) and networks
//!   (`10.0.0.0/8`) reached without a verified certificate. HTTPS is tried
//!   first without checking the certificate, then plain HTTP. Only the
//!   hosts listed: every other registry keeps verified HTTPS, and
//!   credentials only ever go in the clear to a listed host.
//! - `registry-mirrors`: pull-through mirrors of Docker Hub ([`Mirror`]).
//!
//! The daemon reads the file and hands each client a snapshot
//! ([`crate::registry::set_config_source`]).

use std::net::IpAddr;

use crate::mirror::Mirror;
use crate::reference::is_local;

/// One `insecure-registries` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Insecure {
    /// `host` or `host:port`, matched as written, as Docker matches it: an
    /// entry without a port does not cover the same host with one.
    Host(String),
    /// A network in CIDR form: covers a registry whose address is in it.
    Net(IpAddr, u8),
}

impl Insecure {
    /// Docker's spellings: `registry.lan:5000`, `registry.lan`,
    /// `192.168.1.10:5000`, `[fd00::1]:5000`, `10.0.0.0/8`. An `http://` or
    /// `https://` in front is dropped, as Docker drops it. Docker Hub, and a
    /// network that is every address, are refused: insecure is for named
    /// hosts, never for everything.
    pub fn parse(input: &str) -> Result<Insecure, String> {
        let text = input.trim();
        let lower = text.to_ascii_lowercase();
        let bare = lower.strip_prefix("http://").or_else(|| lower.strip_prefix("https://")).unwrap_or(&lower).trim_end_matches('/');
        if bare.is_empty() {
            return Err("an insecure registry needs a host, such as registry.lan:5000".into());
        }
        if let Some((ip, bits)) = bare.split_once('/') {
            let ip: IpAddr = ip.parse().map_err(|_| format!("not a host or a network: {text}"))?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            let bits: u8 = bits.parse().ok().filter(|&b| b <= max).ok_or_else(|| format!("not a network: {text}"))?;
            if bits == 0 {
                return Err(format!("{text} is every address: list the registries' hosts or networks instead"));
            }
            return Ok(Insecure::Net(mask(ip, bits), bits));
        }
        if !valid_host(bare) {
            return Err(format!("not a host or a network: {text}"));
        }
        if is_hub(bare) {
            return Err("Docker Hub is always reached over verified HTTPS".into());
        }
        Ok(Insecure::Host(bare.to_owned()))
    }

    /// As daemon.json keeps it.
    pub fn as_string(&self) -> String {
        match self {
            Insecure::Host(h) => h.clone(),
            Insecure::Net(ip, bits) => format!("{ip}/{bits}"),
        }
    }
}

/// `host[:port]` with a host made of name characters, an IPv4 address, or
/// an IPv6 address in brackets.
fn valid_host(s: &str) -> bool {
    let label = |l: &str| !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    let (host_ok, port) = if let Some(rest) = s.strip_prefix('[') {
        let Some((ip, after)) = rest.split_once(']') else { return false };
        let port = match after {
            "" => None,
            a => match a.strip_prefix(':') {
                Some(p) => Some(p),
                None => return false,
            },
        };
        (ip.parse::<std::net::Ipv6Addr>().is_ok(), port)
    } else {
        let (h, p) = s.rsplit_once(':').map_or((s, None), |(h, p)| (h, Some(p)));
        (h.split('.').all(label), p)
    };
    host_ok && port.is_none_or(|p| p.parse::<u16>().is_ok_and(|p| p > 0))
}

/// Docker Hub's names. Hub is always reached over verified HTTPS: no
/// setting, and no address the name resolves to, changes that.
pub fn is_hub(host: &str) -> bool {
    let name = host_name(host);
    ["docker.io", "index.docker.io", "registry-1.docker.io"].iter().any(|h| name.eq_ignore_ascii_case(h))
}

/// The host of `host[:port]` or `[v6]:port`, without the port.
fn host_name(s: &str) -> &str {
    if let Some(rest) = s.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    // `registry-1.docker.io.` (a trailing dot) is the same name.
    s.rsplit_once(':').map_or(s, |(h, _)| h).trim_end_matches('.')
}

/// A name's addresses, for a network entry. Asked of the system's resolver,
/// as the connection to it will be, and kept a minute: a pull asks for each
/// layer, and the answer is the same.
fn lookup(name: &str) -> Vec<IpAddr> {
    use std::collections::HashMap;
    use std::sync::{LazyLock, Mutex};
    use std::time::{Duration, Instant};
    type Seen = HashMap<String, (Vec<IpAddr>, Instant)>;
    static SEEN: LazyLock<Mutex<Seen>> = LazyLock::new(Default::default);
    if let Some((addrs, at)) = SEEN.lock().unwrap_or_else(|e| e.into_inner()).get(name)
        && at.elapsed() < Duration::from_secs(60)
    {
        return addrs.clone();
    }
    let addrs: Vec<IpAddr> = std::net::ToSocketAddrs::to_socket_addrs(&(name, 0)).map(|a| a.map(|a| a.ip()).collect()).unwrap_or_default();
    let mut seen = SEEN.lock().unwrap_or_else(|e| e.into_inner());
    if seen.len() > 256 {
        seen.clear();
    }
    seen.insert(name.to_owned(), (addrs.clone(), Instant::now()));
    addrs
}

fn mask(ip: IpAddr, bits: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v) => {
            let m = if bits == 0 { 0 } else { u32::MAX << (32 - u32::from(bits)) };
            IpAddr::V4((u32::from(v) & m).into())
        }
        IpAddr::V6(v) => {
            let m = if bits == 0 { 0 } else { u128::MAX << (128 - u32::from(bits)) };
            IpAddr::V6((u128::from(v) & m).into())
        }
    }
}

/// How a registry host is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// Verified HTTPS: every registry nothing below covers.
    Https,
    /// Plain HTTP: a mirror written `http://` when it is asked as the mirror.
    Http,
    /// A registry on this machine (Docker treats loopback as insecure) or
    /// listed in `insecure-registries`: HTTPS without checking the
    /// certificate, else plain HTTP.
    Insecure,
}

/// The registry settings of daemon.json. The default is none: every
/// registry over verified HTTPS, Docker Hub direct.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistryConfig {
    pub insecure: Vec<Insecure>,
    pub mirrors: Vec<Mirror>,
}

impl RegistryConfig {
    /// Whether `host` (`registry.lan:5000`, as a reference names it) is
    /// listed in `insecure-registries`. A network entry covers an address
    /// in it, and a name whose address (looked up as a connection to it
    /// would be) is; names are only looked up when a network is listed.
    /// Docker Hub never is, whatever its name resolves to, and with an empty
    /// list nothing is looked up.
    ///
    /// A name resolving to several addresses is covered when any is in the
    /// network, and the connection to it may then pick another: Docker
    /// matches networks the same way, and the registries a network lists
    /// are on the same LAN.
    pub fn is_insecure(&self, host: &str) -> bool {
        if self.insecure.is_empty() || is_hub(host) {
            return false;
        }
        let host = host.to_ascii_lowercase();
        if self.is_listed_host(&host) {
            return true;
        }
        if !self.insecure.iter().any(|e| matches!(e, Insecure::Net(..))) {
            return false;
        }
        let name = host_name(&host);
        let addrs: Vec<IpAddr> = match name.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => lookup(name),
        };
        self.insecure.iter().any(|e| match e {
            Insecure::Net(net, bits) => addrs.iter().any(|ip| ip.is_ipv4() == net.is_ipv4() && mask(*ip, *bits) == *net),
            Insecure::Host(_) => false,
        })
    }

    /// Whether `host` is written in the list as a host (not reached by a
    /// network): the only way a registry may name another host for its
    /// token service or its blobs and have unchecked TLS or plain HTTP.
    pub fn is_listed_host(&self, host: &str) -> bool {
        if is_hub(host) {
            return false;
        }
        let host = host.to_ascii_lowercase();
        self.insecure.iter().any(|e| matches!(e, Insecure::Host(h) if *h == host))
    }

    /// Whether `host` may be reached without a verified certificate: a
    /// registry on this machine, as Docker treats loopback, or one in the
    /// list. Docker Hub never.
    pub fn is_unverified(&self, host: &str) -> bool {
        !is_hub(host) && (is_local(host) || self.is_insecure(host))
    }

    /// How `host` is reached: Docker Hub always verified, loopback and listed
    /// hosts insecure (HTTPS unchecked, else plain HTTP, as Docker does),
    /// the rest over verified HTTPS. `as_mirror` is a pull of a Docker Hub
    /// image from a mirror (never with credentials): a mirror written
    /// `http://` is asked over plain HTTP then, as Docker asks it, but the
    /// same host named as a registry is like any other.
    pub fn reach(&self, host: &str, as_mirror: bool) -> Reach {
        if is_hub(host) {
            Reach::Https
        } else if as_mirror && self.mirrors.iter().any(|m| m.http && m.host == host) {
            Reach::Http
        } else if self.is_unverified(host) {
            Reach::Insecure
        } else {
            Reach::Https
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(entries: &[&str]) -> RegistryConfig {
        RegistryConfig { insecure: entries.iter().map(|e| Insecure::parse(e).unwrap()).collect(), mirrors: Vec::new() }
    }

    #[test]
    fn entries_are_read_as_docker_reads_them() {
        assert_eq!(Insecure::parse("Registry.LAN:5000").unwrap(), Insecure::Host("registry.lan:5000".into()));
        assert_eq!(Insecure::parse("http://registry.lan:5000/").unwrap(), Insecure::Host("registry.lan:5000".into()));
        assert_eq!(Insecure::parse("https://registry.lan").unwrap(), Insecure::Host("registry.lan".into()));
        assert_eq!(Insecure::parse("[fd00::1]:5000").unwrap(), Insecure::Host("[fd00::1]:5000".into()));
        assert_eq!(Insecure::parse("10.1.2.3/8").unwrap().as_string(), "10.0.0.0/8");
        assert_eq!(Insecure::parse("fd00::/8").unwrap().as_string(), "fd00::/8");
    }

    #[test]
    fn everything_and_docker_hub_are_refused() {
        for bad in ["", " ", "http://", "0.0.0.0/0", "::/0", "docker.io", "index.docker.io", "registry-1.docker.io:443", "reg lan", "reg.lan:port", "reg.lan:0", "10.0.0.0/33", "[nope]:5000", "a..b", "reg.lan/path"] {
            assert!(Insecure::parse(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn only_listed_hosts_are_insecure() {
        let c = cfg(&["registry.lan:5000", "plain.lan"]);
        assert!(c.is_insecure("registry.lan:5000"));
        assert!(c.is_insecure("REGISTRY.lan:5000"));
        // Docker matches the name as written: another port is another registry.
        assert!(!c.is_insecure("registry.lan:5001"));
        assert!(!c.is_insecure("registry.lan"));
        assert!(c.is_insecure("plain.lan"));
        assert!(!c.is_insecure("plain.lan:5000"));
        assert!(!c.is_insecure("ghcr.io"));
        assert!(!RegistryConfig::default().is_insecure("registry.lan:5000"));
    }

    #[test]
    fn a_network_covers_the_addresses_in_it() {
        let c = cfg(&["192.168.7.0/24", "fd00:1::/32"]);
        assert!(c.is_insecure("192.168.7.20:5000"));
        assert!(c.is_insecure("192.168.7.20"));
        assert!(!c.is_insecure("192.168.8.20:5000"));
        assert!(c.is_insecure("[fd00:1::5]:5000"));
        assert!(!c.is_insecure("[fd00:2::5]:5000"));
        // A name is looked up: localhost is 127.0.0.1, not in the network.
        assert!(!c.is_insecure("localhost:5000"));
        assert!(cfg(&["127.0.0.0/8"]).is_insecure("localhost:5000"));
    }

    #[test]
    fn docker_hub_is_never_insecure_whatever_it_resolves_to() {
        // 127.0.0.0/8 is where the hub names would resolve with a hosts-file
        // entry; the network must not cover them.
        let c = cfg(&["10.0.0.0/8", "127.0.0.0/8", "192.168.0.0/16"]);
        for hub in ["docker.io", "index.docker.io", "registry-1.docker.io", "registry-1.docker.io:443", "REGISTRY-1.docker.io"] {
            assert!(!c.is_insecure(hub), "{hub}");
            assert!(!c.is_unverified(hub), "{hub}");
            assert_eq!(c.reach(hub, false), Reach::Https, "{hub}");
        }
        assert!(!RegistryConfig::default().is_insecure("10.1.1.1"));
        // A trailing dot names the same host.
        for hub in ["registry-1.docker.io.", "docker.io.", "index.docker.io.:443"] {
            assert!(is_hub(hub), "{hub}");
            assert!(!c.is_unverified(hub), "{hub}");
        }
    }

    #[test]
    fn a_network_alone_is_not_a_listed_host() {
        let c = cfg(&["10.0.0.0/8", "registry.lan:5000"]);
        assert!(c.is_insecure("10.1.2.3:5000"));
        assert!(!c.is_listed_host("10.1.2.3:5000"));
        assert!(c.is_listed_host("registry.lan:5000"));
    }

    #[test]
    fn each_host_is_reached_its_own_way() {
        let mut c = cfg(&["registry.lan:5000"]);
        c.mirrors = vec![Mirror::parse("http://mirror.lan:5000").unwrap(), Mirror::parse("https://mirror.example.com").unwrap()];
        assert_eq!(c.reach("registry.lan:5000", false), Reach::Insecure);
        assert_eq!(c.reach("localhost:5000", false), Reach::Insecure);
        assert_eq!(c.reach("mirror.lan:5000", true), Reach::Http);
        assert_eq!(c.reach("mirror.example.com", true), Reach::Https);
        assert_eq!(c.reach("ghcr.io", false), Reach::Https);
        // Named as a registry (credentials may go with it), an http://
        // mirror's host is like any other.
        assert_eq!(c.reach("mirror.lan:5000", false), Reach::Https);
        assert_eq!(cfg(&[]).reach("mirror.lan:5000", true), Reach::Https);
    }
}
