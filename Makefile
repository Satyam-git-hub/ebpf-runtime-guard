CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPFCFLAGS += -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH)
INCLUDES := -I. -I/usr/include

.PHONY: all clean vmlinux

all: vmlinux bpf_toctou_detector.o toctou_loader

vmlinux:
	@if [ ! -f vmlinux.h ]; then \
		echo "Generating vmlinux.h..."; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
	fi

bpf_toctou_detector.o: bpf_toctou_detector.bpf.c vmlinux
	$(CLANG) $(BPFCFLAGS) $(INCLUDES) -c $< -o $@

toctou_loader: toctou_loader.c
	gcc -Wall -O2 -o $@ $< -lbpf

clean:
	rm -f *.o toctou_loader vmlinux.h

install:
	sudo ./toctou_loader

test: all
	sudo ./run_test.sh
