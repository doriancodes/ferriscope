# Filtering

## Basic Filter Syntax

Filters use tcpdump/libpcap syntax. Here are common patterns:

### Protocol Filters
```bash
# TCP only
ferriscope -i eth0 -f "tcp"

# UDP only
ferriscope -i eth0 -f "udp"

# ICMP only
ferriscope -i eth0 -f "icmp"
```

### Port Filters
```bash
# Single port
ferriscope -i eth0 -f "port 80"

# Multiple ports
ferriscope -i eth0 -f "port 80 or port 443"

# Port ranges
ferriscope -i eth0 -f "portrange 1-1024"
```

### Host Filters
```bash
# Single host
ferriscope -i eth0 -f "host 192.168.1.1"

# Source host
ferriscope -i eth0 -f "src host 192.168.1.1"

# Destination host
ferriscope -i eth0 -f "dst host 192.168.1.1"
```

## Combining Filters

Use logical operators to combine filters:

```bash
# AND operator
ferriscope -i eth0 -f "tcp and port 80"

# OR operator
ferriscope -i eth0 -f "port 80 or port 443"

# NOT operator
ferriscope -i eth0 -f "not port 22"
```

## Advanced Filters

### TCP Flags
```bash
# SYN packets
ferriscope -i eth0 -f "tcp[tcpflags] & tcp-syn != 0"

# SYN-ACK packets
ferriscope -i eth0 -f "tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)"
```

### Packet Size
```bash
# Packets larger than 1000 bytes
ferriscope -i eth0 -f "greater 1000"

# Packets smaller than 100 bytes
ferriscope -i eth0 -f "less 100"
```
