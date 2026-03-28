# Compile BPF sample programs (CO-RE style with vmlinux.h).
#
# Requires: clang, llvm, linux-tools-common / bpftool, libbpf-dev (headers),
#           kernel BTF at /sys/kernel/btf/vmlinux (typical on modern kernels).

SHELL := /bin/bash

CLANG       ?= clang
LLVM_STRIP  ?= llvm-strip
# Prefer PATH, then common distro locations.
BPFTOOL ?= $(shell for p in $$(command -v bpftool 2>/dev/null) /usr/sbin/bpftool /usr/bin/bpftool; do \
	test -x "$$p" && echo "$$p" && break; done)

ARCH_RAW := $(shell uname -m)
ifeq ($(ARCH_RAW),x86_64)
  BPF_ARCH := x86
else ifeq ($(ARCH_RAW),aarch64)
  BPF_ARCH := arm64
else
  BPF_ARCH := $(ARCH_RAW)
endif

ROOT      := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
VMLINUX_H   := $(ROOT)/include/vmlinux.h
# libbpf headers are <bpf/...> under /usr/include/bpf (libbpf-dev). Arch path is for linux/*.h UAPI.
LIBBPF_CPPFLAGS ?= $(shell pkg-config --silence-errors --cflags libbpf 2>/dev/null)
INCLUDES := -I$(ROOT)/include $(LIBBPF_CPPFLAGS) -I/usr/include -I/usr/include/$(ARCH_RAW)-linux-gnu

# Relative paths so `make samples/foo.o` matches this rule (not the built-in %.o: %.c with cc).
EBFP_DIR := ebpf
BPF_SRCS    := $(wildcard $(EBFP_DIR)/*.c)
BPF_OBJS    := $(BPF_SRCS:.c=.o)

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
	-Wall \
	-fno-stack-protector -fno-jump-tables

.PHONY: all clean vmlinux-h strip list help

help:
	@echo "eBPF toy — BPF sample build"
	@echo "  make / make all  — generate include/vmlinux.h (needs bpftool + kernel BTF) and build ebpf/*.o"
	@echo "  make list        — show discovered sample sources"
	@echo "  make strip       — llvm-strip debug info from built .o files"
	@echo "  make clean       — remove *.o and generated vmlinux.h"
	@echo "  ./scripts/compile-bpf.sh — same as make -C repo root"
	@echo "Variables: BPFTOOL, VMLINUX_BTF (default /sys/kernel/btf/vmlinux), CLANG, LLVM_STRIP, LIBBPF_CPPFLAGS"
	@echo "If bpf_helpers.h is missing: install libbpf-dev (Debian/Ubuntu) or set LIBBPF_CPPFLAGS=-I/path/to/libbpf/include"

all: vmlinux-h $(BPF_OBJS)
	@echo "Built: $(BPF_OBJS)"

list:
	@echo "BPF sources: $(BPF_SRCS)"

vmlinux-h: $(VMLINUX_H)

$(VMLINUX_H): $(VMLINUX_BTF)
	@if [ -z "$(BPFTOOL)" ] || ! [ -x "$(BPFTOOL)" ]; then \
		echo "bpftool not found. Install it (e.g. Ubuntu: sudo apt install linux-tools-common linux-tools-$$(uname -r))" >&2; \
		echo "or set BPFTOOL=/path/to/bpftool" >&2; \
		exit 1; \
	fi
	@mkdir -p $(dir $@)
	@echo "Generating $@ from $(VMLINUX_BTF)"
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

$(EBFP_DIR)/%.o: $(EBFP_DIR)/%.c $(VMLINUX_H)
	@echo "clang (bpf) $<"
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c $< -o $@

strip: $(BPF_OBJS)
	@test -n "$(BPF_OBJS)" || (echo "No objects to strip; run 'make' first" && exit 1)
	$(LLVM_STRIP) -g $(BPF_OBJS)

clean:
	rm -f $(BPF_OBJS) $(VMLINUX_H)
