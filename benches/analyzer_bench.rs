#![feature(test)]

extern crate test;

use criterion::{criterion_group, criterion_main, Criterion};
use ferriscope::analyzer;
use ferriscope::ui::PacketInfo;
use chrono::{DateTime, Utc};

pub fn analyzer_benchmark(c: &mut Criterion) {
    // Create sample TCP packet info
    let mut tcp_packet = PacketInfo {
        timestamp: Utc::now(),
        source: "127.0.0.1".to_string(),
        destination: "192.168.1.1".to_string(),
        protocol: "TCP".to_string(),
        length: 64,
        info: "TCP packet".to_string(),
        raw_data: vec![
            // Sample TCP packet data
            0x45, 0x00, 0x00, 0x28, // IPv4 header
            0x00, 0x00, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x01, // Source IP
            0xc0, 0xa8, 0x01, 0x01  // Dest IP
        ],
    };

    // Create sample UDP packet info
    let mut udp_packet = PacketInfo {
        timestamp: Utc::now(),
        source: "127.0.0.1".to_string(),
        destination: "192.168.1.1".to_string(),
        protocol: "UDP".to_string(),
        length: 32,
        info: "UDP packet".to_string(),
        raw_data: vec![
            // Sample UDP packet data
            0x45, 0x00, 0x00, 0x1c, // IPv4 header
            0x00, 0x00, 0x40, 0x00,
            0x40, 0x11, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x01, // Source IP
            0xc0, 0xa8, 0x01, 0x01  // Dest IP
        ],
    };

    c.bench_function("analyze_tcp_packet", |b| {
        b.iter(|| analyzer::analyze_packet(&mut tcp_packet));
    });

    c.bench_function("analyze_udp_packet", |b| {
        b.iter(|| analyzer::analyze_packet(&mut udp_packet));
    });
}

criterion_group!(benches, analyzer_benchmark);
criterion_main!(benches); 