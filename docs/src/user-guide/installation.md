# Installation

## Prerequisites

Before installing Ferriscope, ensure you have the following prerequisites:

- Rust and Cargo (install from [rustup.rs](https://rustup.rs))
- libpcap development files

### Platform-Specific Requirements

#### Ubuntu/Debian
```bash
sudo apt-get install libpcap-dev
```

#### macOS
```bash
xcode-select --install
```

#### Windows
- Install [Npcap](https://npcap.com/) (with SDK)

## Installation Methods

### From Source
```bash
# Clone the repository
git clone https://github.com/yourusername/ferriscope
cd ferriscope

# Build the project
cargo build --release

# Run Ferriscope
sudo ./target/release/ferriscope
```

### Cargo Install (Coming Soon)
```bash
cargo install ferriscope
```

## Verifying Installation

To verify your installation:

```bash
ferriscope --version
```

## Setting Up Permissions

### Linux
```bash
# Option 1: Run with sudo
sudo ferriscope

# Option 2: Set capabilities (recommended)
sudo setcap cap_net_raw,cap_net_admin=eip target/release/ferriscope
```

### macOS
```bash
# Run with sudo
sudo ferriscope
```

### Windows
Run as Administrator 