# Performance Tuning

## Capture Buffer Size

The capture buffer size affects how many packets can be queued before processing:

```bash
# Increase buffer size on Linux
sudo sysctl -w net.core.rmem_max=2097152
sudo sysctl -w net.core.rmem_default=2097152
```

## Filter Optimization

### Efficient Filters
```bash
# Good - specific and focused
ferriscope -i eth0 -f "tcp port 80"

# Better - using port ranges
ferriscope -i eth0 -f "tcp portrange 80-443"

# Avoid - too broad
ferriscope -i eth0 -f "ip"
```

### Filter Order
Place the most selective filters first:
```bash
# Good
ferriscope -i eth0 -f "port 80 and tcp"

# Less efficient
ferriscope -i eth0 -f "tcp and port 80"
```

## Memory Usage

- Use specific filters to reduce packet capture volume
- Clear packet history periodically using 'c'
- Save to file instead of keeping in memory for long captures

## CPU Usage

Factors affecting CPU usage:
1. Capture filter complexity
2. Packet rate
3. Interface speed
4. Display update frequency

### Tips
- Use simple filters when possible
- Capture on specific ports/protocols
- Avoid capturing all packets without filters
- Use output files for high-volume captures
