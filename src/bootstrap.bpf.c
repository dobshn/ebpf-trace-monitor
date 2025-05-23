// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
/* Modified by dobshn, 2025 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "bootstrap.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * fork() 호출 시, 생성된 자식의 pid를 저장할 map이다.
 */
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 8192);
        __type(key, pid_t);
        __type(value, u8);
} child_pid_store SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} exec_start SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 8192);
        __type(key, pid_t);
        __type(value, struct sock *);
} sock_store SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/*
 * fork() 호출이 일어난 다음 exec()가 호출된 경우, 프로세스 생성으로 간주한다.
 * fork() 호출 시 생성된 자식의 pid를 map에 등록한다.
 * exec() 호출 시 해당 프로세스의 pid가 map에 등록되어 있는지 확인한다.
 * 등록되어 있을 경우에만 프로세스 생성으로 간주한다.
 * 이후 해당 프로세스의 pid를 map에서 제거한다.(연달아 exec 호출하는 경우 방지)
 */
SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
        pid_t child_pid = ctx->child_pid;
        u8 dummy = 1;

        bpf_map_update_elem(&child_pid_store, &child_pid, &dummy, BPF_ANY);
        return 0;
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task;
	unsigned fname_off;
	struct event *e;
	pid_t pid;
	u64 ts;
	u8 *found;

	pid = bpf_get_current_pid_tgid() >> 32;
	
	/* fork를 통해 생성된 프로세스인지 확인 */
	found = bpf_map_lookup_elem(&child_pid_store, &pid);
	if (!found)
		return 0; // fork 없이 exec만 호출된 경우 무시

	/* exec를 통해 프로세스 생성 확정 → map에서 제거 */
	bpf_map_delete_elem(&child_pid_store, &pid);
	
	/* remember time exec() was executed for this PID */
	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

        /* 공통 필드 */
        e->type = EVENT_EXEC;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->timestamp = ts;
	
        /* 특화 필드 */
	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&e->exec.filename, sizeof(e->exec.filename), (void *)ctx + fname_off);

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	struct task_struct *task;
	struct event *e;
	pid_t pid, tid;
	u64 id, ts, *start_ts, duration_ns = 0;

	/* get PID and TID of exiting thread/process */
	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (u32)id;
	ts = bpf_ktime_get_ns();

	/* ignore thread exits */
	if (pid != tid)
		return 0;

	/* if we recorded start of the process, calculate lifetime duration */
	start_ts = bpf_map_lookup_elem(&exec_start, &pid);
	if (start_ts)
		duration_ns = ts - *start_ts;
	bpf_map_delete_elem(&exec_start, &pid);

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

        /* 공통 필드 */
        e->type = EVENT_EXIT;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->timestamp = ts;
	
	/* 특화 필드 */
	e->exit.exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
	e->exit.duration_ns = duration_ns;

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int handle_open(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	struct task_struct *task;
	pid_t pid;
	const char *fname;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	task = (struct task_struct *)bpf_get_current_task();
	pid = bpf_get_current_pid_tgid() >> 32;

	/* 공통 필드 */
	e->type = EVENT_OPEN;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->timestamp = bpf_ktime_get_ns();

	/* 특화 필드 */
	fname = (const char *)ctx->args[1];
	bpf_probe_read_user_str(&e->open.filename, sizeof(e->open.filename), fname);

	/* submit */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/tcp_connect")
int handle_connect_entry(struct pt_regs *ctx)
{
        struct sock *sk;
        pid_t pid;
        
        sk = (struct sock *)PT_REGS_PARM1(ctx);
        pid = bpf_get_current_pid_tgid() >> 32;
        bpf_map_update_elem(&sock_store, &pid, &sk, BPF_ANY);
        return 0;
}

SEC("kretprobe/tcp_connect")
int handle_connect_ret(struct pt_regs *ctx)
{
        struct event *e;
        struct task_struct *task;
        struct sock **skp, *sk;
        pid_t pid;
        int ret;

        ret = PT_REGS_RC(ctx);
        pid = bpf_get_current_pid_tgid() >> 32;

        if (ret != 0) {
            bpf_map_delete_elem(&sock_store, &pid);
            return 0;
        }

        skp = bpf_map_lookup_elem(&sock_store, &pid);
        if (!skp)
            return 0;

        sk = *skp;

        e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (!e)
            return 0;

        task = (struct task_struct *)bpf_get_current_task();

        e->type = EVENT_CONN;
        e->pid = pid;
        e->ppid = BPF_CORE_READ(task, real_parent, tgid);
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        e->timestamp = bpf_ktime_get_ns();

        e->conn.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        e->conn.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        e->conn.dport = __bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

        bpf_ringbuf_submit(e, 0);
        bpf_map_delete_elem(&sock_store, &pid);
        return 0;
}

SEC("uretprobe/bash:readline")
int handle_bash_readline(struct pt_regs *ctx)
{
        const char *line = (const char *)PT_REGS_RC(ctx);
        struct task_struct *task;
        struct event *e;
        pid_t pid;

        e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (!e)
            return 0;

        pid = bpf_get_current_pid_tgid() >> 32;
        task = (struct task_struct *)bpf_get_current_task();

        e->type = EVENT_CMD;
        e->pid = pid;
        e->ppid = BPF_CORE_READ(task, real_parent, tgid);
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        e->timestamp = bpf_ktime_get_ns();

        bpf_probe_read_user_str(&e->cmd.cmd, sizeof(e->cmd.cmd), line);

        bpf_ringbuf_submit(e, 0);
        return 0;
}
