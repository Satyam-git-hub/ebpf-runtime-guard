#!/bin/bash

echo "🛡️  TOCTOU Detection Test Runner 🛡️"
echo "==================================="

# Check if detector is running
if ! pgrep -f "toctou_loader" > /dev/null; then
    echo "❌ TOCTOU detector not running!"
    echo "Please start it in another terminal: sudo ./toctou_loader"
    exit 1
fi

echo "✅ Detector is running"

# Compile test if needed
if [ ! -f test_framework ]; then
    echo "📦 Compiling test framework..."
    gcc -pthread -o test_framework test_framework.c
fi

echo "🚀 Starting TOCTOU attack simulations..."
echo "Watch the detector terminal for alerts!"
echo ""

# Run the test suite
./test_framework

echo ""
echo "📋 Checking kernel ring buffer for TOCTOU detections:"
echo "================================================="
dmesg | tail -20 | grep -E "(TOCTOU|LSM|exec)" --color=always || echo "No TOCTOU alerts in recent kernel messages"

echo ""
echo "🎯 Test Summary:"
echo "- Look for 'TOCTOU DETECTED!' messages in detector output"
echo "- Check for LSM exec messages with different paths"
echo "- Normal execution should NOT trigger TOCTOU alerts"
