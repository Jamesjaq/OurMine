#!/bin/bash
set -e

if [ "${OURMINE_VALIDATION_VM:-}" != "1" ]; then
    echo "ERROR: VM-only validation requires OURMINE_VALIDATION_VM=1 inside a disposable VM worker."
    exit 2
fi

echo "=== OurMine VM Validation Setup ==="

# 1. Verify Node / NPM
if ! command -v node &> /dev/null; then
    echo "ERROR: Node.js not found"
    exit 1
fi

# 2. Check if target server is running, if not start it persistently
if pgrep -f "validation/vm/target_server.js" > /dev/null; then
    echo "Lab target server already running."
else
    echo "Starting lab target server on 127.0.0.1:8080..."
    node validation/vm/start_target.js
    sleep 1
fi

# 3. Health check
if node --experimental-strip-types validation/vm/health.ts; then
    echo ""
    echo "LAB STATUS: READY"
    echo "TARGET: 127.0.0.1:8080"
    echo "SCOPE: 127.0.0.1"
    echo "NETWORK: localhost isolated"
else
    echo "ERROR: Health check failed."
    exit 1
fi
