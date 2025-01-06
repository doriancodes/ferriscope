# Building from Source

## Prerequisites

### Required Tools
- Rust toolchain (1.70.0 or later)
- Cargo
- Git
- C compiler (gcc/clang)
- libpcap development files

### Platform-Specific Setup

#### Linux
```bash
# Ubuntu/Debian
sudo apt-get install build-essential libpcap-dev

# Fedora
sudo dnf install gcc libpcap-devel

# Arch Linux
sudo pacman -S base-devel libpcap
```

#### macOS
```bash
xcode-select --install
```

#### Windows
1. Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
2. Install [Npcap SDK](https://npcap.com/#download)

## Building

### Clone Repository
```bash
git clone https://github.com/yourusername/ferriscope
cd ferriscope
```

### Debug Build
```bash
cargo build
```

### Release Build
```bash
cargo build --release
```

### Running Tests
```bash
# Run all tests
cargo test

# Run specific test
cargo test test_packet_capture

# Run with logging
RUST_LOG=debug cargo test
```

## Development Environment

### Recommended Tools
- VS Code with rust-analyzer
- LLDB or GDB for debugging
- Clippy for linting
- rustfmt for formatting

### VS Code Setup
```json
{
    "rust-analyzer.checkOnSave.command": "clippy",
    "rust-analyzer.cargo.features": ["all"],
    "editor.formatOnSave": true
}
```

### Git Hooks
```bash
#!/bin/sh
# .git/hooks/pre-commit
cargo fmt -- --check
cargo clippy -- -D warnings
cargo test
```
