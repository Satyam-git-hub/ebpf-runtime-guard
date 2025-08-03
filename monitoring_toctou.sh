#!/bin/bash

echo "🛡️ Comprehensive TOCTOU Monitoring Dashboard"
echo "============================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "❌ Must run as root for trace access"
   exit 1
fi

# Setup trace monitoring
echo "🔍 Setting up trace monitoring..."
echo 1 > /sys/kernel/debug/tracing/events/bpf_trace/bpf_trace_printk/enable
echo > /sys/kernel/debug/tracing/trace  # Clear existing traces

# Start detector in background
echo "🚀 Starting TOCTOU detector..."
./toctou_loader &
DETECTOR_PID=$!

# Give detector time to initialize
sleep 2

echo "📊 Starting real-time monitoring (Press Ctrl+C to stop)..."
echo "========================================================="

# Monitor trace_pipe with enhanced filtering and formatting
cat /sys/kernel/debug/tracing/trace_pipe | while read line; do
    if echo "$line" | grep -q "TOCTOU"; then
        echo -e "\033[1;31m🚨 ATTACK: $line\033[0m"
    elif echo "$line" | grep -q "SYSCALL"; then
        echo -e "\033[1;34m📝 SYSCALL: $line\033[0m"
    elif echo "$line" | grep -q "LSM"; then
        echo -e "\033[1;32m📋 LSM: $line\033[0m"
    elif echo "$line" | grep -q "PATH-BASED\|TIMING-BASED\|CONTENT-BASED\|INODE-BASED"; then
        echo -e "\033[1;33m🔍 DETECTION: $line\033[0m"
    fi
done &

MONITOR_PID=$!

# Trap Ctrl+C to cleanup
trap cleanup INT

cleanup() {
    echo -e "\n🛑 Stopping monitoring..."
    kill $DETECTOR_PID 2>/dev/null || true
    kill $MONITOR_PID 2>/dev/null || true
    wait $DETECTOR_PID 2>/dev/null || true
    wait $MONITOR_PID 2>/dev/null || true
    echo "✅ Cleanup completed"
    exit 0
}

# Wait for user interrupt
wait $MONITOR_PID
