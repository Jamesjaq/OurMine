#!/bin/bash
echo "=== OurMine Lab Teardown ==="

if [ -f lab/.target.pid ]; then
    PID=$(cat lab/.target.pid)
    if kill -0 $PID 2>/dev/null; then
        kill $PID
        echo "Stopped target server PID $PID."
    fi
    rm lab/.target.pid
fi

pkill -f "lab/target_server.js" 2>/dev/null || true

rm -rf lab/results/*.json lab/results/*.md 2>/dev/null || true

echo "LAB TEARDOWN COMPLETE."
