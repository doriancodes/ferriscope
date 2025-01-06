use chrono::Utc;
use criterion::{criterion_group, criterion_main, Criterion};
use ferriscope::capture;
use ferriscope::ui::PacketInfo;
use tokio::sync::mpsc;

pub fn capture_benchmark(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("packet_processing", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let (packet_tx, mut packet_rx) = mpsc::channel::<PacketInfo>(1000);

                // Simulate packet capture by sending a test packet
                let test_packet = PacketInfo {
                    timestamp: Utc::now(),
                    source: "192.168.1.1".to_string(),
                    destination: "192.168.1.2".to_string(),
                    protocol: "TCP".to_string(),
                    length: 64,
                    info: "Test packet".to_string(),
                    raw_data: vec![0; 64],
                };

                packet_tx.send(test_packet).await.unwrap();

                // Process one packet
                packet_rx.recv().await
            });
        });
    });

    c.bench_function("filter_processing", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let (packet_tx, _packet_rx) = mpsc::channel::<PacketInfo>(1000);
                let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

                // Start mock capture with filter
                let handle = tokio::spawn(async move {
                    let test_packet = PacketInfo {
                        timestamp: Utc::now(),
                        source: "192.168.1.1".to_string(),
                        destination: "192.168.1.2".to_string(),
                        protocol: "TCP".to_string(),
                        length: 64,
                        info: "Test packet".to_string(),
                        raw_data: vec![0; 64],
                    };

                    // Simulate filter processing
                    if test_packet.protocol == "TCP" {
                        packet_tx.send(test_packet).await.unwrap();
                    }

                    shutdown_rx.recv().await
                });

                // Let it process one packet then shut down
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                shutdown_tx.send(()).await.unwrap();
                handle.await.unwrap()
            });
        });
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = capture_benchmark
);
criterion_main!(benches);
