use pcap::{Device, Capture};
use tokio::sync::mpsc;
use std::error::Error;
use crate::ui::PacketInfo;
use etherparse::{SlicedPacket, InternetSlice, TransportSlice};

pub async fn start_capture(
    interface: Option<String>,
    filter: Option<String>,
    // output: Option<String>,
    mut shutdown_rx: mpsc::Receiver<()>,
    packet_tx: mpsc::Sender<PacketInfo>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    // Get default device if none specified
    let device = match interface {
        Some(name) => Device::list()?
            .into_iter()
            .find(|dev| dev.name == name)
            .ok_or("Device not found")?,
        None => Device::lookup()?.ok_or("No default device found")?
    };

    // Create capture handle
    let mut cap = Capture::from_device(device)?
        .promisc(true)
        .snaplen(65535)
        .immediate_mode(true)
        .open()?;

    // Apply filter if specified
    if let Some(filter_expr) = filter {
        cap.filter(&filter_expr, true)?;
    }

    // Spawn a separate thread for packet capture
    let capture_thread = std::thread::spawn(move || {
        loop {
            if shutdown_rx.try_recv().is_ok() {
                println!("Capture thread received shutdown signal");
                break;
            }

            match cap.next_packet() {
                Ok(packet) => {
                    if let Ok(parsed) = SlicedPacket::from_ethernet(packet.data) {
                        let protocol = get_protocol_name(&parsed);
                        let (source, destination) = match &parsed.ip {
                            Some(InternetSlice::Ipv4(ref header, _)) => {
                                match &parsed.transport {
                                    Some(TransportSlice::Tcp(tcp)) => (
                                        format!("{}:{}", header.source_addr(), tcp.source_port()),
                                        format!("{}:{}", header.destination_addr(), tcp.destination_port())
                                    ),
                                    Some(TransportSlice::Udp(udp)) => (
                                        format!("{}:{}", header.source_addr(), udp.source_port()),
                                        format!("{}:{}", header.destination_addr(), udp.destination_port())
                                    ),
                                    Some(TransportSlice::Unknown(_)) => (
                                        header.source_addr().to_string(),
                                        header.destination_addr().to_string()
                                    ),
                                    _ => (
                                        header.source_addr().to_string(),
                                        header.destination_addr().to_string()
                                    ),
                                }
                            },
                            Some(InternetSlice::Ipv6(ref header, _)) => {
                                match &parsed.transport {
                                    Some(TransportSlice::Tcp(tcp)) => (
                                        format!("{}:{}", header.source_addr(), tcp.source_port()),
                                        format!("{}:{}", header.destination_addr(), tcp.destination_port())
                                    ),
                                    Some(TransportSlice::Udp(udp)) => (
                                        format!("{}:{}", header.source_addr(), udp.source_port()),
                                        format!("{}:{}", header.destination_addr(), udp.destination_port())
                                    ),
                                    Some(TransportSlice::Unknown(_)) => (
                                        header.source_addr().to_string(),
                                        header.destination_addr().to_string()
                                    ),
                                    _ => (
                                        header.source_addr().to_string(),
                                        header.destination_addr().to_string()
                                    ),
                                }
                            },
                            None => ("Unknown".to_string(), "Unknown".to_string()),
                        };

                        let packet_info = PacketInfo {
                            timestamp: chrono::DateTime::from_timestamp(
                                packet.header.ts.tv_sec,
                                packet.header.ts.tv_usec as u32 * 1000
                            ).unwrap_or_default(),
                            protocol,
                            source,
                            destination,
                            length: packet.header.len as usize,
                            info: get_packet_info(&parsed),
                            raw_data: packet.data.to_vec(),
                        };
                        
                        if packet_tx.blocking_send(packet_info).is_err() {
                            break;
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(_) => break,
            }
        }
    });

    // Wait for capture thread to complete
    if let Err(e) = capture_thread.join() {
        eprintln!("Capture thread panicked: {:?}", e);
    }

    Ok(())
}

fn get_protocol_name(packet: &SlicedPacket) -> String {
    match &packet.transport {
        Some(TransportSlice::Tcp(_)) => "TCP".to_string(),
        Some(TransportSlice::Udp(_)) => "UDP".to_string(),
        Some(TransportSlice::Icmpv4(_)) => "ICMPv4".to_string(),
        Some(TransportSlice::Icmpv6(_)) => "ICMPv6".to_string(),
        Some(TransportSlice::Unknown(_)) => "Unknown".to_string(),
        None => match &packet.ip {
            Some(InternetSlice::Ipv4(_, _)) => "IPv4".to_string(),
            Some(InternetSlice::Ipv6(_, _)) => "IPv6".to_string(),
            None => "Unknown".to_string(),
        },
    }
}

fn get_packet_info(packet: &SlicedPacket) -> String {
    match &packet.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            let flags = vec![
                if tcp.syn() { "SYN" } else { "" },
                if tcp.ack() { "ACK" } else { "" },
                if tcp.fin() { "FIN" } else { "" },
                if tcp.rst() { "RST" } else { "" },
                if tcp.psh() { "PSH" } else { "" },
                if tcp.urg() { "URG" } else { "" },
            ];
            flags.into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" ")
        },
        Some(TransportSlice::Udp(_)) => "UDP Datagram".to_string(),
        Some(TransportSlice::Icmpv4(_)) => "ICMP Message".to_string(),
        Some(TransportSlice::Icmpv6(_)) => "ICMPv6 Message".to_string(),
        Some(TransportSlice::Unknown(_)) => "Unknown Protocol".to_string(),
        None => "".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;
    use tokio::time::{timeout, Duration};

    fn has_capture_permissions() -> bool {
        // Try to open the default device
        if let Ok(Some(device)) = Device::lookup() {
            Capture::from_device(device)
                .and_then(|cap| cap.open())
                .is_ok()
        } else {
            false
        }
    }

    #[tokio::test]
    async fn test_start_capture_no_interface() {
        if !has_capture_permissions() {
            println!("Skipping test_start_capture_no_interface: insufficient permissions");
            return;
        }

        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);
        let (packet_tx, _packet_rx) = mpsc::channel::<PacketInfo>(1000);
        
        // Start capture in a separate task
        let capture_handle = tokio::spawn(async move {
            start_capture(
                None, 
                None, 
                // None, 
                shutdown_rx,
                packet_tx
            ).await
        });

        // Send shutdown signal immediately
        shutdown_tx.send(()).await.expect("Failed to send shutdown signal");
        
        // Wait for capture to finish with timeout
        match timeout(Duration::from_secs(5), capture_handle).await {
            Ok(result) => {
                match result {
                    Ok(capture_result) => assert!(capture_result.is_ok()),
                    Err(e) => panic!("Capture thread panicked: {:?}", e),
                }
            },
            Err(_) => panic!("Test timed out"),
        }
    }

    #[tokio::test]
    async fn test_start_capture_with_interface() {
        if !has_capture_permissions() {
            println!("Skipping test_start_capture_with_interface: insufficient permissions");
            return;
        }

        if let Ok(default_dev) = Device::lookup() {
            if let Some(dev) = default_dev {
                let dev_name = dev.name.clone();
                let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);
                let (packet_tx, _packet_rx) = mpsc::channel::<PacketInfo>(1000);
                
                // Start capture in a separate task
                let capture_handle = tokio::spawn(async move {
                    start_capture(
                        Some(dev_name),
                        None,
                        // None,
                        shutdown_rx,
                        packet_tx
                    ).await
                });

                // Send shutdown signal immediately
                shutdown_tx.send(()).await.expect("Failed to send shutdown signal");
                
                // Wait for capture to finish with timeout
                match timeout(Duration::from_secs(5), capture_handle).await {
                    Ok(result) => {
                        match result {
                            Ok(capture_result) => assert!(capture_result.is_ok()),
                            Err(e) => panic!("Capture thread panicked: {:?}", e),
                        }
                    },
                    Err(_) => panic!("Test timed out"),
                }
            }
        }
    }

    #[tokio::test]
    async fn test_start_capture_with_filter() {
        if !has_capture_permissions() {
            println!("Skipping test_start_capture_with_filter: insufficient permissions");
            return;
        }

        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);
        let (packet_tx, _packet_rx) = mpsc::channel::<PacketInfo>(1000);
        
        // Start capture in a separate task
        let capture_handle = tokio::spawn(async move {
            start_capture(
                None,
                Some("tcp".to_string()),
                // None,
                shutdown_rx,
                packet_tx
            ).await
        });

        // Send shutdown signal immediately
        shutdown_tx.send(()).await.expect("Failed to send shutdown signal");
        
        // Wait for capture to finish with timeout
        match timeout(Duration::from_secs(5), capture_handle).await {
            Ok(result) => {
                match result {
                    Ok(capture_result) => assert!(capture_result.is_ok()),
                    Err(e) => panic!("Capture thread panicked: {:?}", e),
                }
            },
            Err(_) => panic!("Test timed out"),
        }
    }

    // These tests don't require capture permissions
    #[tokio::test]
    async fn test_invalid_interface() {
        let (_, shutdown_rx) = mpsc::channel::<()>(1);
        let (packet_tx, _packet_rx) = mpsc::channel::<PacketInfo>(1000);
        
        let result = start_capture(
            Some("invalid_device".to_string()),
            None,
            // None,
            shutdown_rx,
            packet_tx
        ).await;
        
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_filter() {
        let (_, shutdown_rx) = mpsc::channel::<()>(1);
        let (packet_tx, _packet_rx) = mpsc::channel::<PacketInfo>(1000);
        
        let result = start_capture(
            None,
            Some("invalid filter syntax".to_string()),
            // None,
            shutdown_rx,
            packet_tx
        ).await;
        
        assert!(result.is_err());
    }
}
