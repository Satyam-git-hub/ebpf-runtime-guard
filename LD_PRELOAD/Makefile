CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPFCFLAGS += -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH)
INCLUDES := -I. -I/usr/include

.PHONY: all clean vmlinux

all: vmlinux bpf_ldpreload_detector.o security_monitor malicious_preload.so

vmlinux:
	@if [ ! -f vmlinux.h ]; then \
		echo "Generating vmlinux.h..."; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
	fi

bpf_ldpreload_detector.o: bpf_ldpreload_detector.bpf.c vmlinux.h
	@echo "Building eBPF LD_PRELOAD detector..."
	$(CLANG) $(BPFCFLAGS) $(INCLUDES) -c $< -o $@

security_monitor: security_monitor.c bpf_ldpreload_detector.o
	@echo "Building comprehensive security monitor..."
	@echo ""
	@echo "Breakdown of compilation flags:"
	@echo "  -Wall: Enables all compiler warnings"
	@echo "  -O2: Optimization level 2 for performance"
	@echo "  -o security_monitor: Specifies the output executable name"
	@echo "  security_monitor.c: The source file"
	@echo "  -lbpf: Links with libbpf library (needed for eBPF support)"
	@echo ""
	gcc -Wall -O2 -o $@ $< -lbpf
	@echo "✅ Security monitor compiled successfully"

malicious_preload.so: malicious_preload.c
	@echo "Building malicious LD_PRELOAD shared library..."
	@echo ""
	@echo "Breakdown of compilation flags:"
	@echo "  -shared: Creates a shared library (.so file)"
	@echo "  -fPIC: Generates position-independent code (required for shared libraries)"
	@echo "  -o malicious_preload.so: Specifies the output filename"
	@echo "  malicious_preload.c: The source file"
	@echo "  -ldl: Links with the dynamic loading library (needed for dlsym() function)"
	@echo ""
	gcc -shared -fPIC -o $@ $< -ldl
	@echo "✅ Malicious library compiled successfully"

clean:
	rm -f *.o security_monitor malicious_preload.so vmlinux.h
