# Troubleshooting

## Common Issues

### Permission Denied
```
Error: Failed to open capture device 'eth0'. This usually means insufficient permissions.
```

**Solution:**
```bash
# Option 1: Run with sudo
sudo ferriscope

# Option 2: Set capabilities (Linux only)
sudo setcap cap_net_raw,cap_net_admin=eip target/release/ferriscope
```

### Interface Not Found
```
Error: Device not found
```

**Solution:**
1. List available interfaces:
```bash
ferriscope -l
```
2. Use the correct interface name
3. Check if interface is up:
```bash
# Linux
ip link show

# macOS
ifconfig

# Windows
ipconfig
```

### Invalid Filter Syntax
```
Error: Invalid filter expression
```

**Solution:**
1. Check filter syntax
2. Use quotes around complex filters
3. Refer to the [Filter Syntax](../advanced/filter-syntax.md) guide

## Performance Issues

### High CPU Usage
**Symptoms:**
- System slowdown
- Delayed packet display
- UI lag

**Solutions:**
1. Use more specific filters
2. Reduce capture buffer size
3. Clear packet history regularly
4. Save to file instead of keeping in memory

### Memory Issues
**Symptoms:**
- Increasing memory usage
- Slow response time
- System warnings

**Solutions:**
1. Clear packet history (`c` key)
2. Use output files for long captures
3. Apply more specific filters
4. Limit capture duration

## UI Issues

### Terminal Display Problems
**Symptoms:**
- Garbled output
- Missing UI elements
- Incorrect colors

**Solutions:**
1. Check terminal size:
```bash
# Should be at least 80x24
stty size
```
2. Verify terminal supports colors:
```bash
echo $TERM
```
3. Reset terminal:
```bash
reset
```

### Crash Recovery
If the program crashes, restore terminal:
```bash
# Reset terminal
reset

# Or
stty sane
```
