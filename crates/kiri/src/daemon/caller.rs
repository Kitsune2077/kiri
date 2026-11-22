//! Where an API request comes from: this machine's own programs (the CLI,
//! the window, tools run by the person), or a container that was given the
//! engine's socket (`-v /var/run/docker.sock:/var/run/docker.sock`).
//!
//! Docker's API has nothing that changes the daemon's own settings, so a
//! container with the socket cannot change them through it. Kiri's settings
//! endpoints that Docker has no counterpart for stay that way: only this
//! machine's programs may use them.
//!
//! - On a Mac, a container reaches the daemon only through the VM's relay
//!   (ports::serve_engine_api), which marks its connections.
//! - On Linux and in WSL, a container mounts the daemon's socket itself, so
//!   the process at the other end is asked: one in a deeper PID namespace
//!   than the daemon's, or in the cgroup tree Kiri puts its containers in
//!   (kiri-init's host_cgroup), is a container's. One that cannot be looked
//!   at is taken for a container's.

use std::cell::Cell;
use std::os::unix::net::UnixStream;

thread_local! {
    /// The connection served on this thread came through the VM's relay.
    static RELAYED: Cell<bool> = const { Cell::new(false) };
}

/// Marks the connection this thread serves as a container's.
pub fn mark_container() {
    RELAYED.with(|r| r.set(true));
}

/// Whether `conn`, the connection served on this thread, is a container's.
pub fn is_container(conn: &UnixStream) -> bool {
    if RELAYED.with(Cell::get) {
        return true;
    }
    #[cfg(target_os = "linux")]
    {
        linux_peer_is_container(conn)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = conn;
        false
    }
}

#[cfg(target_os = "linux")]
fn linux_peer_is_container(conn: &UnixStream) -> bool {
    use std::os::fd::AsRawFd;
    // SAFETY: a connected socket and zeroed storage for its credentials.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the output pointers are valid and the buffer is the stated size.
    let r = unsafe { libc::getsockopt(conn.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut cred as *mut libc::ucred).cast(), &mut len) };
    if r != 0 || cred.pid <= 0 {
        return true;
    }
    let read = |p: String| std::fs::read_to_string(p).ok();
    match (read("/proc/self/status".into()), read(format!("/proc/{}/status", cred.pid)), read("/proc/self/cgroup".into()), read(format!("/proc/{}/cgroup", cred.pid))) {
        (Some(own_status), Some(peer_status), Some(own_cgroup), Some(peer_cgroup)) => in_container(&own_status, &peer_status, &own_cgroup, &peer_cgroup),
        _ => true,
    }
}

/// Whether a process is a container's, from its `/proc/<pid>/status` and
/// `/proc/<pid>/cgroup` and the daemon's own: a deeper PID namespace (more
/// `NSpid` entries) than the daemon's, or a cgroup in the tree Kiri puts
/// containers in, `kiri` beside the daemon's `kiri-host` (or at the top).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn in_container(own_status: &str, peer_status: &str, own_cgroup: &str, peer_cgroup: &str) -> bool {
    let depth = |s: &str| s.lines().find_map(|l| l.strip_prefix("NSpid:")).map_or(1, |v| v.split_whitespace().count());
    if depth(peer_status) > depth(own_status) {
        return true;
    }
    let path = |s: &str| s.lines().find_map(|l| l.strip_prefix("0::")).map(|p| p.trim().trim_end_matches('/').to_owned());
    let (Some(own), Some(peer)) = (path(own_cgroup), path(peer_cgroup)) else { return false };
    let mut base = own.as_str();
    while let Some(parent) = base.strip_suffix("/kiri-host") {
        base = parent;
    }
    let under = |dir: &str| peer == dir || peer.starts_with(&format!("{dir}/"));
    under(&format!("{base}/kiri")) || under("/kiri")
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "Name:\tkiri\nNSpid:\t4242\n";

    #[test]
    fn a_relayed_connection_is_a_containers() {
        let (a, _b) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            // Not marked: on Linux the other end is this very process.
            assert!(!is_container(&a));
            mark_container();
            assert!(is_container(&a));
        })
        .join()
        .unwrap();
    }

    #[test]
    fn a_process_in_a_container_is_told_apart() {
        let daemon_cg = "0::/system.slice/kiri.service/kiri-host\n";
        // A program the person runs: their session's cgroup, the same namespace.
        assert!(!in_container(HOST, "NSpid:\t9000\n", daemon_cg, "0::/user.slice/user-1000.slice/session-2.scope\n"));
        // A container: its own PID namespace.
        assert!(in_container(HOST, "NSpid:\t9001\t1\n", daemon_cg, "0::/system.slice/kiri.service/kiri/abc\n"));
        // With the host's PID namespace, it is still in Kiri's container tree.
        assert!(in_container(HOST, "NSpid:\t9002\n", daemon_cg, "0::/system.slice/kiri.service/kiri/abc\n"));
        assert!(in_container(HOST, "NSpid:\t9002\n", "0::/user.slice/user-1000.slice/session-2.scope\n", "0::/kiri/abc/sub\n"));
        // A sibling whose name only starts the same is not.
        assert!(!in_container(HOST, "NSpid:\t9003\n", daemon_cg, "0::/system.slice/kiri.service/kiri-other\n"));
        // Kiri inside a container: the daemon is a level down, and so is the CLI beside it.
        let nested = "NSpid:\t77\t5\n";
        assert!(!in_container(nested, "NSpid:\t78\t6\n", "0::/kiri-host\n", "0::/\n"));
        assert!(in_container(nested, "NSpid:\t79\t7\t1\n", "0::/kiri-host\n", "0::/kiri/x\n"));
    }
}
