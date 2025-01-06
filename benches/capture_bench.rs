use criterion::{criterion_group, criterion_main, Criterion};
use ferriscope::capture;
use ferriscope::ui::PacketInfo;
use tokio::sync::mpsc;
use tokio::runtime::Runtime;
use std::sync::Arc;

fn get_test_interface() -> String {
    if cfg!(target_os = "macos") {
        "lo0".to_string()
    } else if cfg!(target_os = "linux") {
        "lo".to_string()
    } else {
        pcap::Device::list()
            .unwrap()
            .first()
            .map(|dev| dev.name.clone())
            .unwrap_or_else(|| "any".to_string())
    }
}

pub fn capture_benchmark(c: &mut Criterion) {
    let runtime = Arc::new(Runtime::new().unwrap());
    let interface = Arc::new(get_test_interface());
    
    let mut config = Criterion::default()
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(1));
    
    // Benchmark capture without filter
    {
        let runtime = Arc::clone(&runtime);
        let interface = Arc::clone(&interface);
        config.bench_function("capture_no_filter", move |b| {
            let interface = Arc::clone(&interface);
            let runtime = Arc::clone(&runtime);
            b.iter(|| {
                let interface = Arc::clone(&interface);
                runtime.block_on(async {
                    let (packet_tx, mut packet_rx) = mpsc::channel::<PacketInfo>(1000);
                    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

                    let interface_inner = Arc::clone(&interface);
                    let capture_handle = tokio::spawn(async move {
                        if let Err(e) = capture::start_capture(
                            Some((*interface_inner).clone()),
                            None,
                            shutdown_rx,
                            packet_tx
                        ).await {
                            eprintln!("Capture error: {}", e);
                        }
                    });

                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => (),
                        _ = packet_rx.recv() => (),
                    }

                    shutdown_tx.send(()).await.unwrap();
                    capture_handle.await.unwrap();
                })
            });
        });
    }

    // Benchmark capture with filter
    {
        let runtime = Arc::clone(&runtime);
        let interface = Arc::clone(&interface);
        config.bench_function("capture_with_filter", move |b| {
            let interface = Arc::clone(&interface);
            let runtime = Arc::clone(&runtime);
            b.iter(|| {
                let interface = Arc::clone(&interface);
                runtime.block_on(async {
                    let (packet_tx, mut packet_rx) = mpsc::channel::<PacketInfo>(1000);
                    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

                    let interface_inner = Arc::clone(&interface);
                    let capture_handle = tokio::spawn(async move {
                        if let Err(e) = capture::start_capture(
                            Some((*interface_inner).clone()),
                            Some("tcp port 80".to_string()),
                            shutdown_rx,
                            packet_tx
                        ).await {
                            eprintln!("Capture error: {}", e);
                        }
                    });

                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => (),
                        _ = packet_rx.recv() => (),
                    }

                    shutdown_tx.send(()).await.unwrap();
                    capture_handle.await.unwrap();
                })
            });
        });
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = capture_benchmark
);
criterion_main!(benches);
