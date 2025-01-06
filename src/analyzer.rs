use crate::ui::PacketInfo;
use dns_parser::Packet as DnsPacket;
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};

pub fn analyze_packet(packet_info: &mut PacketInfo) {
    // Clone the raw data so we can drop the borrow immediately
    let raw_data = packet_info.raw_data.clone();

    // Parse the packet first and store the result
    let sliced = match SlicedPacket::from_ethernet(&raw_data) {
        Ok(s) => s,
        Err(_) => {
            packet_info.info = "Failed to parse packet".to_string();
            return;
        }
    };

    // Set default protocol to link layer
    packet_info.protocol = "Ethernet".to_string();

    // Extract IP information first
    let (ip_proto, src, dst) = match &sliced.ip {
        Some(InternetSlice::Ipv4(ref header, _)) => (
            "IPv4",
            header.source_addr().to_string(),
            header.destination_addr().to_string(),
        ),
        Some(InternetSlice::Ipv6(ref header, _)) => (
            "IPv6",
            header.source_addr().to_string(),
            header.destination_addr().to_string(),
        ),
        None => {
            packet_info.info = "Non-IP packet".to_string();
            return;
        }
    };

    // Set IP information
    packet_info.protocol = ip_proto.to_string();
    packet_info.source = src;
    packet_info.destination = dst;

    // Now analyze transport layer
    analyze_transport(packet_info, &sliced);
}

fn analyze_transport(packet_info: &mut PacketInfo, packet: &SlicedPacket) {
    match &packet.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            packet_info.protocol = "TCP".to_string();
            packet_info.source = format!("{}:{}", packet_info.source, tcp.source_port());
            packet_info.destination =
                format!("{}:{}", packet_info.destination, tcp.destination_port());

            // Add TCP-specific info
            let flags = format!(
                "Flags: {}{}{}{}{}{}",
                if tcp.syn() { "SYN " } else { "" },
                if tcp.ack() { "ACK " } else { "" },
                if tcp.fin() { "FIN " } else { "" },
                if tcp.rst() { "RST " } else { "" },
                if tcp.psh() { "PSH " } else { "" },
                if tcp.urg() { "URG" } else { "" }
            );
            packet_info.info = flags;
        }
        Some(TransportSlice::Udp(udp)) => {
            packet_info.protocol = "UDP".to_string();
            packet_info.source = format!("{}:{}", packet_info.source, udp.source_port());
            packet_info.destination =
                format!("{}:{}", packet_info.destination, udp.destination_port());

            // Check for DNS
            if udp.destination_port() == 53 || udp.source_port() == 53 {
                packet_info.protocol = "DNS".to_string();
                if let Ok(dns) = DnsPacket::parse(packet.payload) {
                    analyze_dns(packet_info, &dns);
                }
            }
        }
        Some(TransportSlice::Icmpv4(icmp)) => {
            packet_info.protocol = "ICMPv4".to_string();
            packet_info.info = format!("Type: {}, Code: {}", icmp.type_u8(), icmp.code_u8());
        }
        Some(TransportSlice::Icmpv6(icmp)) => {
            packet_info.protocol = "ICMPv6".to_string();
            packet_info.info = format!("Type: {}, Code: {}", icmp.type_u8(), icmp.code_u8());
        }
        Some(TransportSlice::Unknown(_)) => {
            packet_info.protocol = "Unknown Transport".to_string();
            packet_info.info = "Unknown transport protocol".to_string();
        }
        None => {
            packet_info.info = "No transport protocol".to_string();
        }
    }
}

fn analyze_dns(packet_info: &mut PacketInfo, dns: &DnsPacket) {
    let query_type = if dns.header.query {
        "Query"
    } else {
        "Response"
    };

    let mut queries = Vec::new();
    for question in &dns.questions {
        queries.push(format!("{}", question.qname));
    }

    packet_info.info = format!("{}: {}", query_type, queries.join(", "));
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn create_basic_packet_info() -> PacketInfo {
        PacketInfo {
            raw_data: Vec::new(),
            protocol: String::new(),
            source: String::new(),
            destination: String::new(),
            info: String::new(),
            length: 0,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_tcp_packet_analysis() {
        let mut packet_info = create_basic_packet_info();

        // Create a mock TCP packet
        let tcp_packet = SlicedPacket {
            link: None,
            vlan: None,
            ip: Some(InternetSlice::Ipv4(
                etherparse::Ipv4HeaderSlice::from_slice(&[
                    0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 192,
                    168, 1, 1, // Source IP
                    192, 168, 1, 2, // Dest IP
                ])
                .unwrap(),
                Default::default(),
            )),
            transport: Some(TransportSlice::Tcp(
                etherparse::TcpHeaderSlice::from_slice(&[
                    0x1f, 0x90, 0x01, 0xbb, // Source port 8080, dest port 443
                    0x00, 0x00, 0x00, 0x00, // Sequence number
                    0x00, 0x00, 0x00, 0x00, // Ack number
                    0x50, 0x12, 0x20, 0x00, // Flags (SYN + ACK)
                    0x00, 0x00, 0x00, 0x00, // Rest of header
                ])
                .unwrap(),
            )),
            payload: &[],
        };

        analyze_transport(&mut packet_info, &tcp_packet);

        assert_eq!(packet_info.protocol, "TCP");
        assert!(packet_info.source.contains("8080"));
        assert!(packet_info.destination.contains("443"));
        assert!(packet_info.info.contains("SYN"));
        assert!(packet_info.info.contains("ACK"));
    }

    #[test]
    fn test_udp_dns_packet_analysis() {
        let mut packet_info = create_basic_packet_info();

        let udp_packet = SlicedPacket {
            link: None,
            vlan: None,
            ip: Some(InternetSlice::Ipv4(
                etherparse::Ipv4HeaderSlice::from_slice(&[
                    0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 8, 8,
                    8, 8, // Source IP (8.8.8.8)
                    192, 168, 1, 1, // Dest IP
                ])
                .unwrap(),
                Default::default(),
            )),
            transport: Some(TransportSlice::Udp(
                etherparse::UdpHeaderSlice::from_slice(&[
                    0x00, 0x35, 0x30, 0x39, // Source port 53, dest port 12345
                    0x00, 0x08, 0x00, 0x00, // Length and checksum
                ])
                .unwrap(),
            )),
            payload: &[],
        };

        analyze_transport(&mut packet_info, &udp_packet);

        assert_eq!(packet_info.protocol, "DNS");
        assert!(packet_info.source.contains("53"));
        assert!(packet_info.destination.contains("12345"));
    }

    #[test]
    fn test_icmpv4_packet_analysis() {
        let mut packet_info = create_basic_packet_info();

        // Create raw data for the packet
        let raw_data = vec![
            // Ethernet header (14 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Destination MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source MAC
            0x08, 0x00, // EtherType (IPv4)
            // IPv4 header
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 192, 168, 1,
            1, // Source IP
            192, 168, 1, 2, // Dest IP
            // ICMP header (8 bytes required)
            0x08, 0x00, // Type (8 = echo request), Code (0)
            0x00, 0x00, // Checksum
            0x00, 0x00, // Identifier
            0x00, 0x00, // Sequence number
        ];

        packet_info.raw_data = raw_data.clone();

        let icmp_packet = SlicedPacket {
            link: None,
            vlan: None,
            ip: Some(InternetSlice::Ipv4(
                etherparse::Ipv4HeaderSlice::from_slice(&raw_data[14..34]).unwrap(),
                Default::default(),
            )),
            transport: Some(TransportSlice::Icmpv4(
                etherparse::Icmpv4Slice::from_slice(&raw_data[34..42]).unwrap(),
            )),
            payload: &[],
        };

        analyze_transport(&mut packet_info, &icmp_packet);

        assert_eq!(packet_info.protocol, "ICMPv4");
        assert!(packet_info.info.contains("Type: 8"));
        assert!(packet_info.info.contains("Code: 0"));
    }

    #[test]
    fn test_ipv6_packet_analysis() {
        let mut packet_info = create_basic_packet_info();

        // Create raw data for the packet
        let raw_data = vec![
            // Ethernet header (14 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Destination MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source MAC
            0x86, 0xDD, // EtherType (IPv6)
            // IPv6 header (40 bytes)
            0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x06,
            0x40, // Ver, TC, Flow Label, Payload Len, Next Header (6=TCP), Hop Limit
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, // Source IP (2001:db8::1)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
            0x00, 0x00, // Dest IP (2001:db8::2)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // TCP header (20 bytes)
            0x1f, 0x90, 0x01, 0xbb, // Source port 8080, dest port 443
            0x00, 0x00, 0x00, 0x00, // Sequence number
            0x00, 0x00, 0x00, 0x00, // Ack number
            0x50, 0x02, 0x20, 0x00, // Header length, flags (SYN)
            0x00, 0x00, 0x00, 0x00, // Checksum, Urgent pointer
        ];

        packet_info.raw_data = raw_data;

        analyze_packet(&mut packet_info);

        assert_eq!(packet_info.protocol, "TCP");
        assert!(packet_info.source.contains("2001:db8"));
        assert!(packet_info.destination.contains("2001:db8"));
        assert!(packet_info.source.contains("8080"));
        assert!(packet_info.destination.contains("443"));
        assert!(packet_info.info.contains("SYN"));
    }
}
