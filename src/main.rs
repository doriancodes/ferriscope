use clap::Parser;
use std::error::Error;
use tokio::sync::mpsc;

use ferriscope::capture;
use ferriscope::ui;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Network interface to capture from
    #[arg(short, long)]
    interface: Option<String>,

    /// Filter expression (tcpdump syntax)
    #[arg(short, long)]
    filter: Option<String>,

    /// Output file for packet capture
    #[arg(short, long)]
    output: Option<String>,

    /// List available network interfaces
    #[arg(short = 'l', long)]
    list: bool,
}

#[tokio::main]
#[allow(clippy::needless_return)]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Args::parse();

    // Create channels
    let (packet_tx, packet_rx) = mpsc::channel::<ui::PacketInfo>(1000);
    let (_shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

    // Initialize the UI with packet receiver
    let mut app = ui::App::new(packet_rx)?;
    
    // Start capture in background
    let _capture_handle = tokio::spawn(async move {
        if let Err(e) = capture::start_capture(
            args.interface,
            args.filter,
            // args.output,
            shutdown_rx,
            packet_tx,
        ).await {
            eprintln!("Capture error: {}", e);
        }
    });

    // Run the UI
    app.run().await?;

    Ok(())
}
