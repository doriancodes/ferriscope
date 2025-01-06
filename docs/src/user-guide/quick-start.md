# Quick Start

## Basic Usage

1. List available network interfaces:
```bash
ferriscope -l
```

2. Start capturing packets:
```bash
sudo ferriscope -i eth0
```

3. Apply a filter:
```bash
sudo ferriscope -i eth0 -f "tcp port 80"
```

## Interface Controls

- Use `↑/↓` to navigate through packets
- Press `q` to quit
- Use `Ctrl+C` to exit

## Common Examples

### Capture HTTP Traffic
```bash
sudo ferriscope -i eth0 -f "tcp port 80 or tcp port 443"
```

### Monitor DNS Queries
```bash
sudo ferriscope -i eth0 -f "udp port 53"
```

### Watch ICMP Traffic
```bash
sudo ferriscope -i eth0 -f "icmp"
``` 