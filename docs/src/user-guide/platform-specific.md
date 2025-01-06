# Platform-Specific Notes

## Linux

### Installation
```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install libpcap-dev

# Fedora
sudo dnf install libpcap-devel

# Arch Linux
sudo pacman -S libpcap
```

### Permissions Setup
1. Temporary (using sudo):
```bash
sudo ferriscope
```

2. Permanent (recommended):
```bash
# Set capabilities
sudo setcap cap_net_raw,cap_net_admin=eip target/release/ferriscope

# Verify capabilities
getcap target/release/ferriscope
```

3. Using network group (alternative):
```bash
# Add user to network group
sudo usermod -a -G network $USER

# Set group permissions
sudo chgrp network target/release/ferriscope
sudo chmod 750 target/release/ferriscope
```

### Interface Names
- `eth0`, `eth1`: Ethernet interfaces
- `wlan0`, `wlan1`: Wireless interfaces
- `enp0s3`: Predictable network interface names
- `lo`: Loopback interface
- `docker0`: Docker bridge interface
- `tun0`, `tap0`: VPN interfaces

### System Configuration
```bash
# Increase capture buffer size
sudo sysctl -w net.core.rmem_max=2097152
sudo sysctl -w net.core.rmem_default=2097152

# Make changes permanent
echo "net.core.rmem_max=2097152" | sudo tee -a /etc/sysctl.conf
echo "net.core.rmem_default=2097152" | sudo tee -a /etc/sysctl.conf
```

## macOS

### Installation
```bash
# Install Xcode Command Line Tools
xcode-select --install

# Using Homebrew (optional)
brew install libpcap
```

### Security Considerations
- macOS requires root privileges for packet capture
- System Integrity Protection (SIP) must be enabled
- Network Extension entitlements may be required for distribution

### Interface Names
- `en0`: Usually Wi-Fi
- `en1`: Usually Ethernet
- `lo0`: Loopback interface
- `bridge0`: Bridge interface
- `utun0`, `utun1`: VPN interfaces
- `awdl0`: Apple Wireless Direct Link

### Performance Tips
```bash
# Increase capture buffer size
sudo sysctl -w net.local.stream.recvspace=2097152
sudo sysctl -w net.local.stream.sendspace=2097152
```

## Windows

### Installation Requirements
1. Install [Npcap](https://npcap.com/) (not WinPcap)
   - Select "Install Npcap in WinPcap API-compatible Mode"
   - Enable "Support raw 802.11 traffic"

2. Install Build Tools:
   - [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
   - Windows SDK
   - C++ build tools

### Interface Names
Windows uses complex interface names:
```powershell
# PowerShell: List interfaces
Get-NetAdapter | Format-Table -Property Name, InterfaceDescription

# Command Prompt: List interfaces
ferriscope.exe -l
```

Example names:
- `\Device\NPF_{GUID}`: Npcap interface format
- `Ethernet`: Standard network adapter
- `Wi-Fi`: Wireless adapter
- `Local Area Connection`: Legacy naming
- `vEthernet`: Hyper-V virtual interfaces

### Running as Administrator
1. Command Prompt (Admin):
```cmd
runas /user:Administrator "ferriscope.exe"
```

2. PowerShell (Admin):
```powershell
Start-Process ferriscope.exe -Verb RunAs
```

3. Create shortcut:
   - Right-click shortcut → Properties
   - Advanced → Run as administrator

### Windows Firewall
You may need to:
1. Allow ferriscope through Windows Firewall
2. Add exception for specific ports
3. Run as Administrator for firewall modifications

### Known Issues
- Some wireless adapters may not support monitor mode
- Virtual adapters may have limited functionality
- Windows Subsystem for Linux (WSL) requires special configuration
- Hyper-V can interfere with packet capture
