# 설정 변수
BPF_PROG     := bootstrap
SRC_DIR      := src
INCLUDE_DIR  := include
OUTPUT       := build
LIBBPF_DIR   := libbpf

ARCH         := arm64
VMLINUX      := $(INCLUDE_DIR)/vmlinux.h

# 컴파일 플래그
CFLAGS       := -g -O2 -Wall
INCLUDES     := -I$(SRC_DIR) -I$(INCLUDE_DIR) -I$(LIBBPF_DIR)/include -I$(LIBBPF_DIR)/include/uapi

.PHONY: all clean

all: $(BPF_PROG)

# Step 1: Compile BPF 프로그램
$(OUTPUT)/$(BPF_PROG).bpf.o: $(SRC_DIR)/$(BPF_PROG).bpf.c $(VMLINUX) | $(OUTPUT)
	clang -target bpf -D__TARGET_ARCH_$(ARCH) -g -O2 \
	    $(INCLUDES) -c $< -o $@

# Step 2: Generate BPF skeleton (bootstrap.skel.h)
$(SRC_DIR)/$(BPF_PROG).skel.h: $(OUTPUT)/$(BPF_PROG).bpf.o
	bpftool gen skeleton $< > $@

# Step 3: Compile 사용자 공간 프로그램
$(OUTPUT)/$(BPF_PROG).o: $(SRC_DIR)/$(BPF_PROG).c $(SRC_DIR)/$(BPF_PROG).skel.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Step 4: 링킹
$(BPF_PROG): $(OUTPUT)/$(BPF_PROG).o $(LIBBPF_DIR)/src/libbpf.a
	$(CC) $(CFLAGS) $^ -lelf -lz -o $@

# 빌드 디렉토리 생성
$(OUTPUT):
	mkdir -p $@

clean:
	rm -rf $(OUTPUT) $(SRC_DIR)/*.skel.h $(BPF_PROG)
