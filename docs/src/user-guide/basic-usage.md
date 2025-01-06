# Basic Usage

## Command Line Options

```bash
USAGE:
    ferriscope [OPTIONS]

OPTIONS:
    -i, --interface <INTERFACE>    Network interface to capture from
    -f, --filter <FILTER>         Filter expression (tcpdump syntax)
    -o, --output <FILE>           Output file for packet capture
    -l, --list                    List available network interfaces
    -h, --help                    Print help information
    -V, --version                 Print version information
```

## Interface Selection

To list available interfaces:
```bash
ferriscope -l
```

Example output:
```
Available network interfaces:
-----------------------------

en0
  Description: Wi-Fi
  Addresses:
    - 192.168.1.100
    - fe80::1234:5678:9abc:def0

lo0
  Description: Loopback Interface
  Addresses:
    - 127.0.0.1
    - ::1
```

## Starting Capture

Basic capture on an interface:
```bash
sudo ferriscope -i eth0
```

Capture with output file:
```bash
sudo ferriscope -i eth0 -o capture.pcap
```

## Understanding the Display

The interface is divided into two main panels:

1. **Packet List** (Top)
   - Timestamp
   - Source/Destination
   - Protocol
   - Length
   - Summary

2. **Packet Details** (Bottom)
   - Full packet information
   - Protocol details
   - Hex dump
   - ASCII representation
