use crate::log::SharedLog;
use crate::modules::firewall::{self, FirewallKind};
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub fn list_interface_names() -> Vec<String> {
    datalink::interfaces()
        .into_iter()
        .filter(|i| i.is_up() && !i.is_loopback())
        .map(|i| i.name)
        .collect()
}

/// Runs until `stop` is set to true. Intended to be spawned on a background
/// thread; logs everything through `log` so the GUI's SIEM tab updates live.
///
/// If `auto_quarantine` is true, a source IP that trips the SYN-flood
/// threshold is automatically passed to the Firewall module's block-IP
/// action (via the OS's own firewall — `netsh`/`ufw`/`pfctl`) instead of
/// only being logged. This is opt-in (default off in Settings) since
/// auto-blocking a real address is more consequential than just alerting.
pub fn run(
    interface_name: String,
    syn_flood_threshold: u32,
    auto_quarantine: bool,
    firewall_kind: FirewallKind,
    stop: Arc<AtomicBool>,
    log: SharedLog,
) {
    let interfaces = datalink::interfaces();
    let interface = match interfaces.into_iter().find(|i| i.name == interface_name) {
        Some(i) => i,
        None => {
            log.alert("NetworkMonitor", format!("Interface '{interface_name}' not found"));
            return;
        }
    };

    let mut rx = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(_tx, rx)) => rx,
        Ok(_) => {
            log.alert("NetworkMonitor", "Unsupported channel type for this interface");
            return;
        }
        Err(e) => {
            log.alert(
                "NetworkMonitor",
                format!("Failed to open capture on {interface_name}: {e} (packet capture usually needs elevated/root privileges)"),
            );
            return;
        }
    };

    log.info("NetworkMonitor", format!("Monitoring started on {interface_name}"));

    // Sliding-window SYN counter per source IP, for a simple flood heuristic.
    let mut syn_counts: HashMap<Ipv4Addr, (u32, Instant)> = HashMap::new();
    let mut already_quarantined: HashSet<Ipv4Addr> = HashSet::new();
    let window = Duration::from_secs(10);

    while !stop.load(Ordering::Relaxed) {
        match rx.next() {
            Ok(packet) => {
                if let Some(eth) = EthernetPacket::new(packet) {
                    if eth.get_ethertype() == EtherTypes::Ipv4 {
                        if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                            if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                                if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                    let syn = tcp.get_flags() & 0x02 != 0;
                                    let ack = tcp.get_flags() & 0x10 != 0;
                                    if syn && !ack {
                                        let src = ipv4.get_source();
                                        let entry = syn_counts.entry(src).or_insert((0, Instant::now()));
                                        if entry.1.elapsed() > window {
                                            *entry = (0, Instant::now());
                                        }
                                        entry.0 += 1;
                                        if entry.0 == syn_flood_threshold {
                                            log.alert(
                                                "NetworkMonitor",
                                                format!(
                                                    "Possible SYN flood from {src}: {} SYNs in {}s",
                                                    entry.0,
                                                    window.as_secs()
                                                ),
                                            );

                                            if auto_quarantine && !already_quarantined.contains(&src) {
                                                already_quarantined.insert(src);
                                                match firewall::block_ip(firewall_kind, &src.to_string(), &log) {
                                                    Ok(_) => log.alert(
                                                        "NetworkMonitor",
                                                        format!("Auto-quarantine: blocked {src} via firewall (auto-quarantine is enabled in Settings)"),
                                                    ),
                                                    Err(e) => log.warn(
                                                        "NetworkMonitor",
                                                        format!("Auto-quarantine failed for {src}: {e}"),
                                                    ),
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                log.warn("NetworkMonitor", format!("Read error: {e}"));
            }
        }
    }

    log.info("NetworkMonitor", "Monitoring stopped");
}
