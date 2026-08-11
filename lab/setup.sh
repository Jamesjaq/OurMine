#!/bin/bash
set -e

echo "=== OurMine Lab Setup ==="

# 1. Verify Node / NPM
if ! command -v node &> /dev/null; then
    echo "ERROR: Node.js not found"
    exit 1
fi

# 2. Check if target server is running, if not start it persistently
if pgrep -f "lab/target_server.js" > /dev/null; then
    echo "Lab target server already running."
else
    echo "Starting lab target server on 127.0.0.1:8080..."
    node --experimental-strip-types lab/start_target.ts
    sleep 1
fi

# 3. Health check
if node --experimental-strip-types lab/health.ts; then
    echo ""
    echo "LAB STATUS: READY"
    echo "TARGET: 127.0.0.1:8080"
    echo "SCOPE: 127.0.0.1"
    echo "NETWORK: localhost isolated"
else
    echo "ERROR: Health check failed."
    exit 1
fi
