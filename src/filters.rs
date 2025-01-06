use std::str::FromStr;
use crate::ui::PacketInfo;

#[derive(Debug)]
pub struct PacketFilter {
    protocol: Option<Protocol>,
    port: Option<u16>,
    host: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Dns,
}

impl FromStr for Protocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(Protocol::Tcp),
            "udp" => Ok(Protocol::Udp),
            "icmp" => Ok(Protocol::Icmp),
            "dns" => Ok(Protocol::Dns),
            _ => Err("Invalid protocol".to_string()),
        }
    }
}

impl PacketFilter {
    pub fn new() -> Self {
        Self {
            protocol: None,
            port: None,
            host: None,
        }
    }

    pub fn matches(&self, packet: &PacketInfo) -> bool {
        // Check protocol match if filter is set
        if let Some(proto) = &self.protocol {
            let packet_proto = match packet.protocol.to_uppercase().as_str() {
                "TCP" => Protocol::Tcp,
                "UDP" => Protocol::Udp,
                "ICMP" | "ICMPV4" | "ICMPV6" => Protocol::Icmp,
                "DNS" => Protocol::Dns,
                _ => return false,
            };
            if packet_proto != *proto {
                return false;
            }
        }

        // Check port match if filter is set
        if let Some(port) = self.port {
            let has_port = packet.source.contains(&format!(":{}", port)) ||
                          packet.destination.contains(&format!(":{}", port));
            if !has_port {
                return false;
            }
        }

        // Check host match if filter is set
        if let Some(host) = &self.host {
            let source_host = packet.source.split(':').next().unwrap_or("");
            let dest_host = packet.destination.split(':').next().unwrap_or("");
            if source_host != host && dest_host != host {
                return false;
            }
        }

        // If all filters pass (or none were set), return true
        true
    }
}

pub fn parse_filter(expression: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Create a temporary capture handle to validate the filter
    let cap = pcap::Capture::<pcap::Inactive>::from_device("any")?;
    let mut cap = cap.promisc(true)
                    .snaplen(65535)
                    .timeout(1000)
                    .open()?;
    
    // Try to set the filter with optimization enabled
    match cap.filter(expression, true) {
        Ok(_) => Ok(expression.to_string()),
        Err(e) => Err(Box::new(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn create_test_packet(protocol: &str, port: Option<u16>, host: &str) -> PacketInfo {
        PacketInfo {
            raw_data: Vec::new(),
            protocol: protocol.to_string(),
            source: if let Some(p) = port {
                format!("{}:{}", host, p)
            } else {
                host.to_string()
            },
            destination: String::new(),
            info: String::new(),
            length: 0,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_protocol_filter() {
        let mut filter = PacketFilter::new();
        filter.protocol = Some(Protocol::Tcp);

        let tcp_packet = create_test_packet("TCP", Some(80), "192.168.1.1");
        let udp_packet = create_test_packet("UDP", Some(53), "192.168.1.1");
        
        assert!(filter.matches(&tcp_packet));
        assert!(!filter.matches(&udp_packet));
    }

    #[test]
    fn test_port_filter() {
        let mut filter = PacketFilter::new();
        filter.port = Some(80);

        let http_packet = create_test_packet("TCP", Some(80), "192.168.1.1");
        let https_packet = create_test_packet("TCP", Some(443), "192.168.1.1");
        
        assert!(filter.matches(&http_packet));
        assert!(!filter.matches(&https_packet));
    }

    #[test]
    fn test_host_filter() {
        let mut filter = PacketFilter::new();
        filter.host = Some("192.168.1.1".to_string());

        let matching_packet = create_test_packet("TCP", Some(80), "192.168.1.1");
        let non_matching_packet = create_test_packet("TCP", Some(80), "192.168.1.2");
        
        assert!(filter.matches(&matching_packet));
        assert!(!filter.matches(&non_matching_packet));
    }

    #[test]
    fn test_combined_filters() {
        let mut filter = PacketFilter::new();
        filter.protocol = Some(Protocol::Tcp);
        filter.port = Some(80);
        filter.host = Some("192.168.1.1".to_string());

        let matching_packet = create_test_packet("TCP", Some(80), "192.168.1.1");
        let wrong_protocol = create_test_packet("UDP", Some(80), "192.168.1.1");
        let wrong_port = create_test_packet("TCP", Some(443), "192.168.1.1");
        let wrong_host = create_test_packet("TCP", Some(80), "192.168.1.2");
        
        assert!(filter.matches(&matching_packet));
        assert!(!filter.matches(&wrong_protocol));
        assert!(!filter.matches(&wrong_port));
        assert!(!filter.matches(&wrong_host));
    }

    #[test]
    fn test_protocol_from_str() {
        assert_eq!(Protocol::from_str("tcp").unwrap(), Protocol::Tcp);
        assert_eq!(Protocol::from_str("TCP").unwrap(), Protocol::Tcp);
        assert_eq!(Protocol::from_str("udp").unwrap(), Protocol::Udp);
        assert_eq!(Protocol::from_str("UDP").unwrap(), Protocol::Udp);
        assert_eq!(Protocol::from_str("icmp").unwrap(), Protocol::Icmp);
        assert_eq!(Protocol::from_str("ICMP").unwrap(), Protocol::Icmp);
        assert_eq!(Protocol::from_str("dns").unwrap(), Protocol::Dns);
        assert_eq!(Protocol::from_str("DNS").unwrap(), Protocol::Dns);
        
        assert!(Protocol::from_str("invalid").is_err());
    }

    #[test]
    fn test_empty_filter() {
        let filter = PacketFilter::new();
        let packet = create_test_packet("TCP", Some(80), "192.168.1.1");
        
        assert!(filter.matches(&packet), "Empty filter should match all packets");
    }

    #[test]
    fn test_partial_filters() {
        let mut filter = PacketFilter::new();
        filter.protocol = Some(Protocol::Tcp);
        // port and host are None

        let tcp_packet = create_test_packet("TCP", Some(80), "192.168.1.1");
        let udp_packet = create_test_packet("UDP", Some(53), "192.168.1.1");
        
        assert!(filter.matches(&tcp_packet));
        assert!(!filter.matches(&udp_packet));
    }

    #[test]
    fn test_parse_valid_filter() {
        let result = parse_filter("tcp port 80");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "tcp port 80");
    }

    #[test]
    fn test_parse_invalid_filter() {
        let result = parse_filter("invalid filter");
        assert!(result.is_err());
    }
}