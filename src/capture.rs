use crate::ui::PacketInfo;
use chrono::Utc;
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use pcap::{Capture, Device};
use std::error::Error;
use tokio::sync::mpsc;

fn get_protocol_name(packet: &SlicedPacket) -> String {
    match &packet.transport {
        Some(TransportSlice::Tcp(_)) => "TCP".to_string(),
        Some(TransportSlice::Udp(_)) => "UDP".to_string(),
        Some(TransportSlice::Icmpv4(_)) => "ICMPv4".to_string(),
        Some(TransportSlice::Icmpv6(_)) => "ICMPv6".to_string(),
        Some(TransportSlice::Unknown(_)) => "Unknown".to_string(),
        None => "Other".to_string(),
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
            flags
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" ")
        }
        Some(TransportSlice::Udp(_)) => "UDP Datagram".to_string(),
        Some(TransportSlice::Icmpv4(_)) => "ICMP Message".to_string(),
        Some(TransportSlice::Icmpv6(_)) => "ICMPv6 Message".to_string(),
        Some(TransportSlice::Unknown(_)) => "Unknown Protocol".to_string(),
        None => "".to_string(),
    }
}

pub async fn start_capture(
    interface: Option<String>,
    filter: Option<String>,
    output: Option<String>,
    mut shutdown_rx: mpsc::Receiver<()>,
    packet_tx: mpsc::Sender<PacketInfo>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    // Get default device if none specified
    let device = match interface {
        Some(name) => Device::list()?
            .into_iter()
            .find(|dev| dev.name == name)
            .ok_or("Device not found")?,
        None => Device::lookup()?.ok_or("No default device found")?,
    };

    // Create capture handle
    let mut cap = Capture::from_device(device)?
        .promisc(true)
        .snaplen(65535)
        .timeout(1000)
        .immediate_mode(true)
        .open()?;

    // Apply filter if specified
    if let Some(filter) = filter {
        cap.filter(&filter, true)?;
    }

    // Create pcap writer if output specified
    let mut pcap_writer = if let Some(path) = output {
        println!("Creating pcap file at {}", path);
        let pcap_dead = pcap::Capture::dead(cap.get_datalink())?;
        Some(pcap_dead.savefile(&path)?)
    } else {
        None
    };

    println!("Starting packet capture...");

    // Start capture loop
    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                println!("Capture thread received shutdown signal");
                if let Some(writer) = pcap_writer.as_mut() {
                    writer.flush()?;
                }
                break;
            }

            _ = async {
                while let Ok(packet) = cap.next_packet() {
                    // Write to pcap file if enabled
                    if let Some(writer) = pcap_writer.as_mut() {
                        writer.write(&packet);
                        writer.flush()?;
                        println!("Wrote packet: {} bytes", packet.len());
                    }

                    // Parse packet for UI
                    if let Ok(parsed) = SlicedPacket::from_ethernet(packet.data) {
                        let protocol = get_protocol_name(&parsed);
                        let info = get_packet_info(&parsed);
                        let (source, destination) = match &parsed.ip {
                            Some(InternetSlice::Ipv4(ref header, _)) => match &parsed.transport {
                                Some(TransportSlice::Tcp(tcp)) => (
                                    format!("{}:{}", header.source_addr(), tcp.source_port()),
                                    format!("{}:{}", header.destination_addr(), tcp.destination_port()),
                                ),
                                Some(TransportSlice::Udp(udp)) => (
                                    format!("{}:{}", header.source_addr(), udp.source_port()),
                                    format!("{}:{}", header.destination_addr(), udp.destination_port()),
                                ),
                                Some(TransportSlice::Unknown(_)) => (
                                    header.source_addr().to_string(),
                                    header.destination_addr().to_string(),
                                ),
                                _ => (
                                    header.source_addr().to_string(),
                                    header.destination_addr().to_string(),
                                ),
                            },
                            Some(InternetSlice::Ipv6(ref header, _)) => match &parsed.transport {
                                Some(TransportSlice::Tcp(tcp)) => (
                                    format!("{}:{}", header.source_addr(), tcp.source_port()),
                                    format!("{}:{}", header.destination_addr(), tcp.destination_port()),
                                ),
                                Some(TransportSlice::Udp(udp)) => (
                                    format!("{}:{}", header.source_addr(), udp.source_port()),
                                    format!("{}:{}", header.destination_addr(), udp.destination_port()),
                                ),
                                Some(TransportSlice::Unknown(_)) => (
                                    header.source_addr().to_string(),
                                    header.destination_addr().to_string(),
                                ),
                                _ => (
                                    header.source_addr().to_string(),
                                    header.destination_addr().to_string(),
                                ),
                            },
                            None => ("Unknown".to_string(), "Unknown".to_string()),
                        };

                        let packet_info = PacketInfo {
                            timestamp: Utc::now(),
                            source,
                            destination,
                            protocol,
                            length: packet.len(),
                            info,
                            raw_data: packet.to_vec(),
                        };

                        if packet_tx.send(packet_info).await.is_err() {
                            if let Some(writer) = pcap_writer.as_mut() {
                                writer.flush()?;
                            }
                            break;
                        }
                    }
                }
                Ok::<_, Box<dyn Error + Send + Sync>>(())
            } => {}
        }
    }

    // Final flush
    if let Some(mut writer) = pcap_writer {
        println!("Flushing and closing pcap file");
        writer.flush()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;
    use tokio::time::{timeout, Duration};

    fn has_capture_permissions() -> bool {
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

        let capture_handle =
            tokio::spawn(
                async move { start_capture(None, None, None, shutdown_rx, packet_tx).await },
            );

        shutdown_tx
            .send(())
            .await
            .expect("Failed to send shutdown signal");

        match timeout(Duration::from_secs(5), capture_handle).await {
            Ok(result) => match result {
                Ok(capture_result) => assert!(capture_result.is_ok()),
                Err(e) => panic!("Capture thread panicked: {:?}", e),
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

                let capture_handle = tokio::spawn(async move {
                    start_capture(Some(dev_name), None, None, shutdown_rx, packet_tx).await
                });

                shutdown_tx
                    .send(())
                    .await
                    .expect("Failed to send shutdown signal");

                match timeout(Duration::from_secs(5), capture_handle).await {
                    Ok(result) => match result {
                        Ok(capture_result) => assert!(capture_result.is_ok()),
                        Err(e) => panic!("Capture thread panicked: {:?}", e),
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

        let capture_handle = tokio::spawn(async move {
            start_capture(None, Some("tcp".to_string()), None, shutdown_rx, packet_tx).await
        });

        shutdown_tx
            .send(())
            .await
            .expect("Failed to send shutdown signal");

        match timeout(Duration::from_secs(5), capture_handle).await {
            Ok(result) => match result {
                Ok(capture_result) => assert!(capture_result.is_ok()),
                Err(e) => panic!("Capture thread panicked: {:?}", e),
            },
            Err(_) => panic!("Test timed out"),
        }
    }

    #[tokio::test]
    async fn test_invalid_interface() {
        let (_, shutdown_rx) = mpsc::channel::<()>(1);
        let (packet_tx, _packet_rx) = mpsc::channel::<PacketInfo>(1000);

        let result = start_capture(
            Some("invalid_device".to_string()),
            None,
            None,
            shutdown_rx,
            packet_tx,
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_filter() {
        let (_, shutdown_rx) = mpsc::channel::<()>(1);
        let (packet_tx, _packet_rx) = mpsc::channel::<PacketInfo>(1000);

        let result = start_capture(
            None,
            Some("invalid filter syntax".to_string()),
            None,
            shutdown_rx,
            packet_tx,
        )
        .await;

        assert!(result.is_err());
    }
}
