#!/bin/bash
# Simple HTTP requests
curl http://example.com
# DNS queries
dig google.com
# TCP traffic on specific ports
nc -l 12345 &
nc localhost 12345