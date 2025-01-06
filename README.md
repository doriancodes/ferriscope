# Ferriscope 🦀

A high-performance network packet analyzer written in Rust. Ferriscope provides real-time packet capture capabilities with an elegant terminal user interface, making network traffic analysis both powerful and user-friendly.

## Features

- 🚀 Real-time packet capture and analysis
- 🖥️ Modern terminal user interface powered by ratatui
- 🔍 Advanced packet filtering using tcpdump syntax
- 📊 Detailed protocol analysis
- 💾 PCAP file export support (coming soon)
- 🛡️ Support for common protocols (TCP, UDP, ICMP, DNS)
- 🎨 Color-coded packet information (coming soon)
- 📝 Hex dump view with ASCII representation (coming soon)

## Installation

### Prerequisites

- Rust and Cargo (install from [rustup.rs](https://rustup.rs))
- libpcap development files:
  ```bash
  # Ubuntu/Debian
  sudo apt-get install libpcap-dev
  
  # macOS (included in Xcode Command Line Tools)
  xcode-select --install
  
  # Windows
  # Install Npcap from https://npcap.com/ (with SDK)
  ```

### Building from Source

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/ferriscope
   cd ferriscope
   ```

2. Install dependencies:
   ```bash
   # Ubuntu/Debian
   sudo apt-get update
   sudo apt-get install -y build-essential libpcap-dev pkg-config

   # macOS with Homebrew
   xcode-select --install
   brew install libpcap pkg-config

   # Windows
   # Download and install Npcap SDK from https://npcap.com/#download
   # Add the SDK path to your environment variables:
   # NPCAP_SDK=C:\Path\To\Npcap\SDK
   ```

3. Build the project:
   ```bash
   # Debug build
   cargo build

   # Release build (recommended for better performance)
   cargo build --release
   ```

4. Run the binary:
   ```bash
   # Debug build
   cargo run -- --help

   # Release build
   ./target/release/ferriscope --help

   # With sudo (required for packet capture)
   sudo ./target/release/ferriscope -i eth0
   ```

### Troubleshooting Build Issues

#### Linux
- **Permission Denied**: Run capture with sudo or set capabilities:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip target/release/ferriscope
  ```

- **Missing libpcap.so**: Install libpcap development files:
  ```bash
  sudo apt-get install libpcap-dev  # Debian/Ubuntu
  sudo yum install libpcap-devel    # RHEL/CentOS
  sudo dnf install libpcap-devel    # Fedora
  ```

#### macOS
- **XCode Command Line Tools**: Ensure they're installed:
  ```bash
  xcode-select --install
  ```

- **Homebrew Dependencies**: Install required packages:
  ```bash
  brew install libpcap pkg-config
  ```

#### Windows
- **Npcap SDK Not Found**: Set environment variable:
  ```powershell
  # PowerShell (User)
  $env:NPCAP_SDK = "C:\Path\To\Npcap\SDK"
  [System.Environment]::SetEnvironmentVariable("NPCAP_SDK", $env:NPCAP_SDK, "User")

  # Command Prompt (System)
  setx NPCAP_SDK "C:\Path\To\Npcap\SDK" /M
  ```

- **Missing Visual C++ Build Tools**: Install from:
  - Visual Studio Installer or
  - [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)

### Development Build

For development with debug symbols and faster compilation:
```bash
# Build and run with debug features
cargo run -- -i eth0

# Run tests
cargo test

# Run specific test
cargo test test_packet_capture
```

### Production Build

For optimal performance and smaller binary size:
```bash
# Release build with optimizations
cargo build --release

# Strip debug symbols (Linux/macOS)
strip target/release/ferriscope

# Run with release optimizations
cargo run --release -- -i eth0
```

### Cross-Compilation

For building on different target platforms:
```bash
# Add target
rustup target add x86_64-unknown-linux-musl

# Build for Linux with static linking
cargo build --target x86_64-unknown-linux-musl --release

# Build for Windows (from Linux/macOS)
cargo build --target x86_64-pc-windows-gnu --release
```

## Commands

### Basic Usage

```bash
# List all available network interfaces
sudo ferriscope

# Start capturing on a specific interface
sudo ferriscope -i eth0

# Capture with a filter (tcpdump syntax)
sudo ferriscope -i eth0 -f "tcp port 80"

# Save capture to file
sudo ferriscope -i eth0 -o capture.pcap
```

### Common Filter Examples

```bash
# HTTP traffic
sudo ferriscope -i eth0 -f "tcp port 80 or tcp port 443"

# DNS queries
sudo ferriscope -i eth0 -f "udp port 53"

# ICMP (ping) traffic
sudo ferriscope -i eth0 -f "icmp"

# Traffic from/to specific host
sudo ferriscope -i eth0 -f "host 192.168.1.1"

# Traffic on specific ports
sudo ferriscope -i eth0 -f "port 22 or port 80"

# Complex filters
sudo ferriscope -i eth0 -f "tcp[tcpflags] & (tcp-syn|tcp-fin) != 0"

# Filter by packet size
sudo ferriscope -i eth0 -f "greater 1000"

# Exclude certain traffic
sudo ferriscope -i eth0 -f "not port 22"
```

### Development Commands

```bash
# Build and run (debug)
cargo build
sudo ./target/debug/ferriscope -i eth0

# Build and run (release)
cargo build --release
sudo ./target/release/ferriscope -i eth0

# Run tests
cargo test

# Run specific test
cargo test test_packet_capture
```

### Interface Controls

```
↑/↓  - Navigate through packets
q    - Quit application
Ctrl+C - Exit program
```

### Platform-Specific Notes

#### Linux
```bash
# Set capabilities (alternative to sudo)
sudo setcap cap_net_raw,cap_net_admin=eip target/release/ferriscope

# List available interfaces
ip link show
```

#### macOS
```bash
# List available interfaces
networksetup -listallhardwareports

# Common interface names
en0 - Wi-Fi
en1 - Thunderbolt Ethernet
lo0 - Loopback
```

#### Windows (PowerShell as Administrator)
```powershell
# List available interfaces
Get-NetAdapter

# Run capture
.\ferriscope.exe -i Ethernet
```

### Tips

- Use specific filters to reduce CPU load
- Monitor terminal output for performance warnings
- Save to file for long-term analysis
- Use interface name from system's network configuration
- Check permissions if capture fails to start