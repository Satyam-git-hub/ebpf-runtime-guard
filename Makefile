# Common Makefile for eBPF Runtime Guard Project
# Handles both TOCTOU detection and LD_PRELOAD detection modules

CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPFCFLAGS += -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH)
INCLUDES := -I. -I/usr/include

# Define source directories
TOCTOU_DIR := TOCTOU-lsm
LDPRELOAD_DIR := LD_PRELOAD

# Define targets
TOCTOU_BPF_OBJ := $(TOCTOU_DIR)/bpf_toctou_detector.o
TOCTOU_LOADER := $(TOCTOU_DIR)/toctou_loader
TOCTOU_TEST := $(TOCTOU_DIR)/enhanced_toctou_test
TOCTOU_FRAMEWORK := $(TOCTOU_DIR)/test_framework

LDPRELOAD_BPF_OBJ := $(LDPRELOAD_DIR)/bpf_ldpreload_detector.o
LDPRELOAD_MONITOR := $(LDPRELOAD_DIR)/security_monitor
LDPRELOAD_MALICIOUS := $(LDPRELOAD_DIR)/malicious_preload.so

.PHONY: all clean toctou ldpreload test-toctou test-ldpreload install-toctou install-ldpreload vmlinux help

# Default target - builds both modules
all: toctou ldpreload

# Help target
help:
	@echo "eBPF Runtime Guard - Available targets:"
	@echo ""
	@echo "Build targets:"
	@echo "  all              - Build both TOCTOU and LD_PRELOAD modules"
	@echo "  toctou           - Build TOCTOU detection module only"
	@echo "  ldpreload        - Build LD_PRELOAD detection module only"
	@echo "  vmlinux          - Generate vmlinux.h header"
	@echo ""
	@echo "Test targets:"
	@echo "  test-toctou      - Run TOCTOU attack tests"
	@echo "  test-ldpreload   - Run LD_PRELOAD injection tests"
	@echo ""
	@echo "Install targets:"
	@echo "  install-toctou   - Run TOCTOU detector"
	@echo "  install-ldpreload- Run LD_PRELOAD monitor"
	@echo ""
	@echo "Utility targets:"
	@echo "  clean            - Clean all build artifacts"
	@echo "  clean-toctou     - Clean TOCTOU artifacts only"
	@echo "  clean-ldpreload  - Clean LD_PRELOAD artifacts only"

# Generate vmlinux.h (shared by both modules)
vmlinux:
	@if [ ! -f vmlinux.h ]; then \
		echo "Generating vmlinux.h..."; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
	fi

# TOCTOU Detection Module Targets
$(TOCTOU_BPF_OBJ): $(TOCTOU_DIR)/bpf_toctou_detector.bpf.c vmlinux
	@echo "Building TOCTOU eBPF program..."
	$(CLANG) $(BPFCFLAGS) $(INCLUDES) -c $< -o $@

$(TOCTOU_LOADER): $(TOCTOU_DIR)/toctou_loader.c
	@echo "Building TOCTOU user-space loader..."
	gcc -Wall -O2 -o $@ $< -lbpf

$(TOCTOU_TEST): $(TOCTOU_DIR)/enhanced_toctou_test.c
	@echo "Building TOCTOU test suite..."
	gcc -Wall -O2 -o $@ $< -lpthread

$(TOCTOU_FRAMEWORK): $(TOCTOU_DIR)/test_framework.c
	@echo "Building TOCTOU test framework..."
	gcc -Wall -O2 -o $@ $< -lpthread

toctou: $(TOCTOU_BPF_OBJ) $(TOCTOU_LOADER) $(TOCTOU_TEST) $(TOCTOU_FRAMEWORK)
	@echo "✅ TOCTOU detection module built successfully"

# LD_PRELOAD Detection Module Targets
$(LDPRELOAD_BPF_OBJ): $(LDPRELOAD_DIR)/bpf_ldpreload_detector.bpf.c vmlinux
	@echo "Building LD_PRELOAD eBPF program..."
	$(CLANG) $(BPFCFLAGS) $(INCLUDES) -c $< -o $@

$(LDPRELOAD_MONITOR): $(LDPRELOAD_DIR)/security_monitor.c
	@echo "Building LD_PRELOAD security monitor..."
	gcc -Wall -O2 -o $@ $< -lbpf

$(LDPRELOAD_MALICIOUS): $(LDPRELOAD_DIR)/malicious_preload.c
	@echo "Building test malicious library..."
	gcc -shared -fPIC -o $@ $< -ldl

ldpreload: $(LDPRELOAD_BPF_OBJ) $(LDPRELOAD_MONITOR) $(LDPRELOAD_MALICIOUS)
	@echo "✅ LD_PRELOAD detection module built successfully"

# Test Targets
# test-toctou: toctou
# 	@echo "🧪 Running TOCTOU attack test suite..."
# 	@echo "----------------------------------------"
# 	@if [ -f $(TOCTOU_DIR)/run_toctou_tests.sh ]; then \
# 		chmod +x $(TOCTOU_DIR)/run_toctou_tests.sh && \
# 		cd $(TOCTOU_DIR) && ./run_toctou_tests.sh; \
# 	else \
# 		echo "Manual test: Run './$(TOCTOU_TEST)' in another terminal"; \
# 		echo "Then start detector with: 'sudo ./$(TOCTOU_LOADER)'"; \
# 	fi

test-toctou: toctou
	@echo "🧪 Testing TOCTOU attack detection..."
	@echo "-------------------------------------"
	@echo "1. In Terminal 1: sudo ./$(TOCTOU_LOADER)"
	@echo "2. In Terminal 2: ./$(TOCTOU_FRAMEWORK)"
	@echo "3. Watch for TOCTOU detection alerts in Terminal 1"
	@echo ""
	@echo "Alternative tests:"
	@echo "  ./$(TOCTOU_TEST)   # Enhanced content detection tests"
	@echo ""
	@echo "Monitor commands:"
	@echo "  sudo dmesg | tail -20"
	@echo "  sudo cat /sys/kernel/debug/tracing/trace_pipe | grep TOCTOU"


test-ldpreload: ldpreload
	@echo "🧪 Testing LD_PRELOAD detection..."
	@echo "-----------------------------------"
	@echo "1. In Terminal 1: sudo ./$(LDPRELOAD_MONITOR)"
	@echo "2. In Terminal 2: LD_PRELOAD=./$(LDPRELOAD_MALICIOUS) /bin/ls"
	@echo "3. Watch for injection alerts in Terminal 1"

# Install/Run Targets
install-toctou: toctou
	@echo "🚀 Starting TOCTOU detector (requires sudo)..."
	sudo ./$(TOCTOU_LOADER)

install-ldpreload: ldpreload
	@echo "🚀 Starting LD_PRELOAD monitor (requires sudo)..."
	sudo ./$(LDPRELOAD_MONITOR)

# Clean Targets
clean-toctou:
	@echo "🧹 Cleaning TOCTOU artifacts..."
	rm -f $(TOCTOU_BPF_OBJ) $(TOCTOU_LOADER) $(TOCTOU_TEST) $(TOCTOU_FRAMEWORK)
	rm -f $(TOCTOU_DIR)/vmlinux.h

clean-ldpreload:
	@echo "🧹 Cleaning LD_PRELOAD artifacts..."
	rm -f $(LDPRELOAD_BPF_OBJ) $(LDPRELOAD_MONITOR) $(LDPRELOAD_MALICIOUS)
	rm -f $(LDPRELOAD_DIR)/vmlinux.h

clean: clean-toctou clean-ldpreload
	@echo "🧹 Cleaning common artifacts..."
	rm -f vmlinux.h

# Development targets
dev-toctou: clean-toctou toctou
	@echo "🔄 TOCTOU module rebuilt for development"

dev-ldpreload: clean-ldpreload ldpreload
	@echo "🔄 LD_PRELOAD module rebuilt for development"

# Debug targets (show variables)
debug:
	@echo "Build configuration:"
	@echo "  ARCH: $(ARCH)"
	@echo "  CLANG: $(CLANG)"
	@echo "  BPFCFLAGS: $(BPFCFLAGS)"
	@echo "  INCLUDES: $(INCLUDES)"
	@echo ""
	@echo "TOCTOU targets:"
	@echo "  BPF Object: $(TOCTOU_BPF_OBJ)"
	@echo "  Loader: $(TOCTOU_LOADER)"
	@echo "  Tests: $(TOCTOU_TEST), $(TOCTOU_FRAMEWORK)"
	@echo ""
	@echo "LD_PRELOAD targets:"
	@echo "  BPF Object: $(LDPRELOAD_BPF_OBJ)"
	@echo "  Monitor: $(LDPRELOAD_MONITOR)"
	@echo "  Malicious lib: $(LDPRELOAD_MALICIOUS)"

# Enhanced Makefile for eBPF Runtime Guard Project
# Now with automated testing capabilities

# CLANG ?= clang
# ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# BPFCFLAGS += -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH)
# INCLUDES := -I. -I/usr/include

# # Define source directories
# TOCTOU_DIR := TOCTOU-lsm
# LDPRELOAD_DIR := LD_PRELOAD

# # Define targets
# TOCTOU_BPF_OBJ := $(TOCTOU_DIR)/bpf_toctou_detector.o
# TOCTOU_LOADER := $(TOCTOU_DIR)/toctou_loader
# TOCTOU_TEST := $(TOCTOU_DIR)/enhanced_toctou_test
# TOCTOU_FRAMEWORK := $(TOCTOU_DIR)/test_framework

# LDPRELOAD_BPF_OBJ := $(LDPRELOAD_DIR)/bpf_ldpreload_detector.o
# LDPRELOAD_MONITOR := $(LDPRELOAD_DIR)/security_monitor
# LDPRELOAD_MALICIOUS := $(LDPRELOAD_DIR)/malicious_preload.so

# .PHONY: all clean toctou ldpreload test-toctou test-ldpreload test-ldpreload-tmux install-toctou install-ldpreload vmlinux help

# # Default target - builds both modules
# all: toctou ldpreload

# # Help target
# help:
# 	@echo "eBPF Runtime Guard - Available targets:"
# 	@echo ""
# 	@echo "Build targets:"
# 	@echo "  all              - Build both TOCTOU and LD_PRELOAD modules"
# 	@echo "  toctou           - Build TOCTOU detection module only"
# 	@echo "  ldpreload        - Build LD_PRELOAD detection module only"
# 	@echo "  vmlinux          - Generate vmlinux.h header"
# 	@echo ""
# 	@echo "Test targets:"
# 	@echo "  test-toctou      - Run TOCTOU attack tests"
# 	@echo "  test-ldpreload   - Run automated LD_PRELOAD injection tests"
# 	@echo "  test-ldpreload-tmux - Run LD_PRELOAD tests in tmux session"
# 	@echo "  test-all         - Run both test suites"
# 	@echo ""
# 	@echo "Install targets:"
# 	@echo "  install-toctou   - Run TOCTOU detector"
# 	@echo "  install-ldpreload- Run LD_PRELOAD monitor"
# 	@echo ""
# 	@echo "Utility targets:"
# 	@echo "  clean            - Clean all build artifacts"
# 	@echo "  demo-ldpreload   - Interactive LD_PRELOAD demo"

# # Generate vmlinux.h (shared by both modules)
# vmlinux:
# 	@if [ ! -f vmlinux.h ]; then \
# 		echo "Generating vmlinux.h..."; \
# 		bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
# 	fi

# # TOCTOU Detection Module Targets
# $(TOCTOU_BPF_OBJ): $(TOCTOU_DIR)/bpf_toctou_detector.bpf.c vmlinux
# 	@echo "Building TOCTOU eBPF program..."
# 	$(CLANG) $(BPFCFLAGS) $(INCLUDES) -c $< -o $@

# $(TOCTOU_LOADER): $(TOCTOU_DIR)/toctou_loader.c
# 	@echo "Building TOCTOU user-space loader..."
# 	gcc -Wall -O2 -o $@ $< -lbpf

# $(TOCTOU_TEST): $(TOCTOU_DIR)/enhanced_toctou_test.c
# 	@echo "Building TOCTOU test suite..."
# 	gcc -Wall -O2 -o $@ $< -lpthread

# $(TOCTOU_FRAMEWORK): $(TOCTOU_DIR)/test_framework.c
# 	@echo "Building TOCTOU test framework..."
# 	gcc -Wall -O2 -o $@ $< -lpthread

# toctou: $(TOCTOU_BPF_OBJ) $(TOCTOU_LOADER) $(TOCTOU_TEST) $(TOCTOU_FRAMEWORK)
# 	@echo "✅ TOCTOU detection module built successfully"

# # LD_PRELOAD Detection Module Targets
# $(LDPRELOAD_BPF_OBJ): $(LDPRELOAD_DIR)/bpf_ldpreload_detector.bpf.c vmlinux
# 	@echo "Building LD_PRELOAD eBPF program..."
# 	$(CLANG) $(BPFCFLAGS) $(INCLUDES) -c $< -o $@

# $(LDPRELOAD_MONITOR): $(LDPRELOAD_DIR)/security_monitor.c
# 	@echo "Building LD_PRELOAD security monitor..."
# 	gcc -Wall -O2 -o $@ $< -lbpf

# $(LDPRELOAD_MALICIOUS): $(LDPRELOAD_DIR)/malicious_preload.c
# 	@echo "Building test malicious library..."
# 	gcc -shared -fPIC -o $@ $< -ldl

# ldpreload: $(LDPRELOAD_BPF_OBJ) $(LDPRELOAD_MONITOR) $(LDPRELOAD_MALICIOUS)
# 	@echo "✅ LD_PRELOAD detection module built successfully"

# # Enhanced Test Targets with Automation
# test-toctou: toctou
# 	@echo "🧪 Running TOCTOU attack test suite..."
# 	@echo "----------------------------------------"
# 	@if [ -f $(TOCTOU_DIR)/run_toctou_tests.sh ]; then \
# 		chmod +x $(TOCTOU_DIR)/run_toctou_tests.sh && \
# 		cd $(TOCTOU_DIR) && ./run_toctou_tests.sh; \
# 	else \
# 		echo "Manual test: Run './$(TOCTOU_TEST)' in another terminal"; \
# 		echo "Then start detector with: 'sudo ./$(TOCTOU_LOADER)'"; \
# 	fi

# # Automated LD_PRELOAD testing with background processes
# test-ldpreload: ldpreload
# 	@echo "🚀 Running Automated LD_PRELOAD Detection Test"
# 	@echo "=============================================="
# 	@echo "📋 Starting security monitor in background..."
# 	@sudo ./$(LDPRELOAD_MONITOR) > /tmp/ldpreload_monitor.log 2>&1 & \
# 	MONITOR_PID=$$!; \
# 	echo "🔍 Monitor PID: $$MONITOR_PID"; \
# 	sleep 3; \
# 	echo ""; \
# 	echo "🧪 Running LD_PRELOAD injection tests..."; \
# 	echo ""; \
# 	echo "Test 1: Basic LD_PRELOAD injection"; \
# 	echo "-----------------------------------"; \
# 	LD_PRELOAD=./$(LDPRELOAD_MALICIOUS) /bin/echo "Test command executed" || true; \
# 	sleep 2; \
# 	echo ""; \
# 	echo "Test 2: LD_PRELOAD with suspicious path"; \
# 	echo "----------------------------------------"; \
# 	cp ./$(LDPRELOAD_MALICIOUS) /tmp/evil.so; \
# 	LD_PRELOAD=/tmp/evil.so /bin/ls -la /tmp/ | head -3 || true; \
# 	sleep 2; \
# 	echo ""; \
# 	echo "Test 3: LD_PRELOAD with multiple binaries"; \
# 	echo "------------------------------------------"; \
# 	LD_PRELOAD=./$(LDPRELOAD_MALICIOUS) /usr/bin/whoami || true; \
# 	LD_PRELOAD=./$(LDPRELOAD_MALICIOUS) /bin/pwd || true; \
# 	sleep 2; \
# 	echo ""; \
# 	echo "🛑 Stopping security monitor..."; \
# 	sudo kill $$MONITOR_PID 2>/dev/null || true; \
# 	sleep 1; \
# 	echo ""; \
# 	echo "📊 Detection Results:"; \
# 	echo "===================="; \
# 	if [ -f /tmp/ldpreload_monitor.log ]; then \
# 		echo "Monitor output:"; \
# 		cat /tmp/ldpreload_monitor.log; \
# 		echo ""; \
# 		DETECTIONS=$$(grep -c "LD_PRELOAD INJECTION" /tmp/ldpreload_monitor.log 2>/dev/null || echo "0"); \
# 		echo "🎯 Total LD_PRELOAD detections: $$DETECTIONS"; \
# 		if [ $$DETECTIONS -gt 0 ]; then \
# 			echo "✅ LD_PRELOAD detection is working!"; \
# 		else \
# 			echo "❌ No LD_PRELOAD detections found. Check monitor logs."; \
# 		fi; \
# 		rm -f /tmp/ldpreload_monitor.log; \
# 	else \
# 		echo "❌ Monitor log not found"; \
# 	fi; \
# 	rm -f /tmp/evil.so

# # tmux-based interactive testing session
# test-ldpreload-tmux: ldpreload
# 	@echo "🚀 Starting LD_PRELOAD Test Session in tmux"
# 	@echo "============================================"
# 	@if ! command -v tmux >/dev/null 2>&1; then \
# 		echo "❌ tmux not installed. Install with: sudo apt install tmux"; \
# 		exit 1; \
# 	fi
# 	@echo "Creating tmux session 'ldpreload-test'..."
# 	@tmux new-session -d -s ldpreload-test -x 120 -y 30
# 	@tmux split-window -h -t ldpreload-test
# 	@tmux send-keys -t ldpreload-test:0.0 'echo "🛡️ LD_PRELOAD Security Monitor"' Enter
# 	@tmux send-keys -t ldpreload-test:0.0 'echo "=============================="' Enter
# 	@tmux send-keys -t ldpreload-test:0.0 'echo "Starting monitor in 3 seconds..."' Enter
# 	@tmux send-keys -t ldpreload-test:0.0 'sleep 3 && sudo ./$(LDPRELOAD_MONITOR)' Enter
# 	@tmux send-keys -t ldpreload-test:0.1 'echo "🧪 LD_PRELOAD Attack Simulator"' Enter
# 	@tmux send-keys -t ldpreload-test:0.1 'echo "==============================="' Enter
# 	@tmux send-keys -t ldpreload-test:0.1 'echo ""' Enter
# 	@tmux send-keys -t ldpreload-test:0.1 'echo "Available test commands:"' Enter
# 	@tmux send-keys -t ldpreload-test:0.1 'echo "1. LD_PRELOAD=./$(LDPRELOAD_MALICIOUS) /bin/ls"' Enter
# 	@tmux send-keys -t ldpreload-test:0.1 'echo "2. LD_PRELOAD=./$(LDPRELOAD_MALICIOUS) /bin/whoami"' Enter
# 	@tmux send-keys -t ldpreload-test:0.1 'echo "3. cp ./$(LDPRELOAD_MALICIOUS) /tmp/evil.so && LD_PRELOAD=/tmp/evil.so /bin/echo test"' Enter
# 	@tmux send-keys -t ldpreload-test:0.1 'echo ""' Enter
# 	@tmux send-keys -t ldpreload-test:0.1 'echo "Press Ctrl+C in left pane to stop monitor"' Enter
# 	@tmux send-keys -t ldpreload-test:0.1 'echo "Type 'exit' to close session"' Enter
# 	@echo ""
# 	@echo "🎯 tmux session created! Use these commands:"
# 	@echo "  tmux attach -t ldpreload-test   # Attach to session"
# 	@echo "  tmux kill-session -t ldpreload-test  # Kill session"
# 	@echo ""
# 	@echo "Session will auto-attach in 2 seconds..."
# 	@sleep 2
# 	@tmux attach -t ldpreload-test

# # Combined test suite
# test-all: test-toctou test-ldpreload
# 	@echo "🎉 All tests completed!"

# # Interactive demo
# demo-ldpreload: ldpreload
# 	@echo "🎭 Interactive LD_PRELOAD Demo"
# 	@echo "============================="
# 	@echo ""
# 	@echo "This demo will:"
# 	@echo "1. Start the security monitor"
# 	@echo "2. Run various LD_PRELOAD attacks"
# 	@echo "3. Show detection results"
# 	@echo ""
# 	@read -p "Press Enter to continue..." dummy
# 	@$(MAKE) test-ldpreload

# # Install/Run Targets
# install-toctou: toctou
# 	@echo "🚀 Starting TOCTOU detector (requires sudo)..."
# 	sudo ./$(TOCTOU_LOADER)

# install-ldpreload: ldpreload
# 	@echo "🚀 Starting LD_PRELOAD monitor (requires sudo)..."
# 	sudo ./$(LDPRELOAD_MONITOR)

# # Clean Targets
# clean-toctou:
# 	@echo "🧹 Cleaning TOCTOU artifacts..."
# 	rm -f $(TOCTOU_BPF_OBJ) $(TOCTOU_LOADER) $(TOCTOU_TEST) $(TOCTOU_FRAMEWORK)
# 	rm -f $(TOCTOU_DIR)/vmlinux.h

# clean-ldpreload:
# 	@echo "🧹 Cleaning LD_PRELOAD artifacts..."
# 	rm -f $(LDPRELOAD_BPF_OBJ) $(LDPRELOAD_MONITOR) $(LDPRELOAD_MALICIOUS)
# 	rm -f $(LDPRELOAD_DIR)/vmlinux.h

# clean: clean-toctou clean-ldpreload
# 	@echo "🧹 Cleaning common artifacts..."
# 	rm -f vmlinux.h
# 	rm -f /tmp/ldpreload_monitor.log /tmp/evil.so

# # Development targets
# dev-toctou: clean-toctou toctou
# 	@echo "🔄 TOCTOU module rebuilt for development"

# dev-ldpreload: clean-ldpreload ldpreload
# 	@echo "🔄 LD_PRELOAD module rebuilt for development"

# # Debug targets
# debug:
# 	@echo "Build configuration:"
# 	@echo "  ARCH: $(ARCH)"
# 	@echo "  CLANG: $(CLANG)"
# 	@echo "  BPFCFLAGS: $(BPFCFLAGS)"
# 	@echo "  INCLUDES: $(INCLUDES)"
