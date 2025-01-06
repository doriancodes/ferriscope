use criterion::{criterion_group, criterion_main, Criterion};
use ferriscope::filters;
use ferriscope::ui::PacketInfo;
use chrono::Utc;

pub fn filter_benchmark(c: &mut Criterion) {
    // Initialize pcap with loopback interface and no promiscuous mode
    let _ = pcap::Capture::<pcap::Inactive>::from_device("lo0")  // lo0 is macOS loopback
        .unwrap()
        .promisc(false)  // Explicitly disable promiscuous mode
        .snaplen(65535)
        .timeout(1000)
        .immediate_mode(true)  // Add immediate mode for better performance
        .open()
        .unwrap();

    let packet_info = PacketInfo {
        timestamp: Utc::now(),
        source: "127.0.0.1".to_string(),
        destination: "192.168.1.1".to_string(),
        protocol: "TCP".to_string(),
        length: 64,
        info: "TCP packet".to_string(),
        raw_data: vec![
            0x45, 0x00, 0x00, 0x28,
            0x00, 0x00, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x01,
            0xc0, 0xa8, 0x01, 0x01
        ],
    };

    // Test filter parsing
    c.bench_function("parse_simple_filter", |b| {
        b.iter(|| filters::parse_filter("tcp port 80"));
    });

    c.bench_function("parse_complex_filter", |b| {
        b.iter(|| filters::parse_filter("(tcp and port 80) or (udp and port 53)"));
    });

    // Test filter matching - avoid unwrap here
    if let Ok(filter) = filters::parse_filter("tcp port 80") {
        c.bench_function("filter_matching", |b| {
            b.iter(|| filter == packet_info.protocol);
        });
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = filter_benchmark
);
criterion_main!(benches);