CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPFCFLAGS += -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH)
INCLUDES := -I. -I/usr/include

.PHONY: all clean vmlinux

all: vmlinux bpf_ldpreload_detector.o security_monitor

vmlinux:
	@if [ ! -f vmlinux.h ]; then \
		echo "Generating vmlinux.h..."; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
	fi

bpf_ldpreload_detector.o: bpf_ldpreload_detector.bpf.c vmlinux
	$(CLANG) $(BPFCFLAGS) $(INCLUDES) -c $< -o $@

security_monitor: security_monitor.c
	gcc -Wall -O2 -o $@ $< -lbpf

clean:
	rm -f *.o security_monitor vmlinux.h


