# Filter Syntax

## Protocol Filters

### Layer 2 (Data Link)
```bash
# Ethernet
ether host 00:11:22:33:44:55
ether src host 00:11:22:33:44:55
ether dst host 00:11:22:33:44:55
```

### Layer 3 (Network)
```bash
# IPv4
ip
ip6
arp
rarp
```

### Layer 4 (Transport)
```bash
# TCP/UDP
tcp
udp
icmp
icmp6
```

## Packet Characteristics

### Size Filters
```bash
# Length
len <= 128
greater 64
less 1500
```

### TCP Flags
```bash
# Individual flags
tcp[tcpflags] & tcp-syn != 0
tcp[tcpflags] & tcp-ack != 0
tcp[tcpflags] & tcp-fin != 0
tcp[tcpflags] & tcp-rst != 0

# Flag combinations
tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)
```

## Complex Expressions

### Boolean Operations
```bash
# AND
tcp and port 80
host 192.168.1.1 and not port 22

# OR
port 80 or port 443
tcp or udp

# NOT
not port 22
not broadcast
```

### Grouping
```bash
# Use parentheses
(tcp or udp) and port 53
(src host 192.168.1.1 and tcp) or (dst host 192.168.1.2 and udp)
```

## Special Filters

### Broadcast/Multicast
```bash
broadcast
multicast
not broadcast and not multicast
```

### VLAN
```bash
vlan 100
vlan and ip
```
