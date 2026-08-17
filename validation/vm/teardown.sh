#!/bin/bash
echo "=== OurMine Lab Teardown ==="

if [ -f validation/vm/.target.pid ]; then
    PID=$(cat validation/vm/.target.pid)
    if kill -0 $PID 2>/dev/null; then
        kill $PID
        echo "Stopped target server PID $PID."
    fi
    rm validation/vm/.target.pid
fi

pkill -f "validation/vm/target_server.js" 2>/dev/null || true

rm -rf validation/vm/results/*.json validation/vm/results/*.md 2>/dev/null || true

echo "LAB TEARDOWN COMPLETE."
