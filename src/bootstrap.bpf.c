// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bootstrap.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/*
 * uretprobe를 사용해 bash 프로그램의 readline 함수가 종료될 때 해당 프로그램이 실행된다.
 * pt_regs *ctx는 해당 시점의 CPU 레지스터 셋의 정보를 가지고 있다.
 */
SEC("uretprobe/bash:readline")
int handle_bash_readline(struct pt_regs *ctx) {
    const char *line;
    struct event *e;
    /*
     * PT_REGS_RC(ctx)는 레지스터 집합 중에서 함수의 반환 값을 저장하는 레지스터의 값을 반환한다.
     * readline 함수의 반환 값은 사용자가 입력한 명령어 문자열의 주소이다.
     * 이를 const char * 타입으로 캐스팅하여 line 변수에 저장한다.
     */
    line = (const char *)PT_REGS_RC(ctx);
    
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 1;
    
    /*
     * line 변수에 담긴 값은, "사용자 공간에서" readline 함수가 반환한 문자열의 주소다.
     * 따라서, 해당 주소는 커널 메모리가 아닌 사용자 메모리에서 유의미하다.
     * 일반적으로 커널 공간에서 사용자 공간의 메모리에 직접 접근하는 것은 불가능하다.
     * 이는 bpf_probe_read_user_str 헬퍼 함수를 통해 구현할 수 있다.
     * 결국 사용자 공간에서 문자열을 읽어와 현재 커널에 있는 event 구조체의 line 필드에 저장한다.
     */
    bpf_probe_read_user_str(&e->line, sizeof(e->line), line);
    
    bpf_ringbuf_submit(e, 0);
    
    return 0;
}
