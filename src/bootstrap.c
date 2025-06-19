// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
/* Modified by dobshn, 2025 */

#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include "bootstrap.h"
#include "bootstrap.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

// ctx 파라미터로 시간 보정 오프셋을 받습니다.
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    // 컨텍스트에서 오프셋 값을 가져옵니다.
    long long *offset = (long long *)ctx;
	const struct event *e = data;
    // 부팅 기준 타임스탬프에 오프셋을 더해 Unix 시간을 계산합니다.
    unsigned long long corrected_timestamp = e->timestamp + *offset;

	if (e->type == EVENT_EXEC) {
		printf("{\"type\": \"exec\", "
		       "\"timestamp\": %llu, "
		       "\"pid\": %d, "
		       "\"ppid\": %d, "
		       "\"comm\": \"%s\", "
		       "\"filename\": \"%s\"}\n",
		       corrected_timestamp,
		       e->pid,
		       e->ppid,
		       e->comm,
		       e->exec.filename);
	} else if (e->type == EVENT_EXIT) {
		printf("{\"type\": \"exit\", "
		       "\"timestamp\": %llu, "
		       "\"pid\": %d, "
		       "\"ppid\": %d, "
		       "\"comm\": \"%s\", "
		       "\"exit_code\": %u, "
		       "\"duration_ms\": %llu}\n",
		       corrected_timestamp,
		       e->pid,
		       e->ppid,
		       e->comm,
		       e->exit.exit_code,
		       e->exit.duration_ns / 1000000);
	} else if (e->type == EVENT_OPEN) {
		printf("{\"type\": \"open\", "
		       "\"timestamp\": %llu, "
		       "\"pid\": %d, "
		       "\"ppid\": %d, "
		       "\"comm\": \"%s\", "
		       "\"filename\": \"%s\"}\n",
		       corrected_timestamp,
		       e->pid,
		       e->ppid,
		       e->comm,
		       e->open.filename);
	} else if (e->type == EVENT_CONN) {
	    char saddr_str[INET_ADDRSTRLEN], daddr_str[INET_ADDRSTRLEN];
	    
	    inet_ntop(AF_INET, &e->conn.saddr, saddr_str, sizeof(saddr_str));
	    inet_ntop(AF_INET, &e->conn.daddr, daddr_str, sizeof(daddr_str));
	    
		printf("{\"type\": \"conn\", "
		       "\"timestamp\": %llu, "
		       "\"pid\": %d, "
		       "\"ppid\": %d, "
		       "\"comm\": \"%s\", "
		       "\"saddr\": \"%s\", "
		       "\"daddr\": \"%s\", "
		       "\"dport\": %d}\n",
		       corrected_timestamp,
		       e->pid,
		       e->ppid,
		       e->comm,
		       saddr_str,
		       daddr_str,
		       e->conn.dport);
	} else if (e->type == EVENT_CMD) {
		printf("{\"type\": \"cmd\", "
		       "\"timestamp\": %llu, "
		       "\"pid\": %d, "
		       "\"ppid\": %d, "
		       "\"comm\": \"%s\", "
		       "\"cmd\": \"%s\"}\n",
		       corrected_timestamp,
		       e->pid,
		       e->ppid,
		       e->comm,
		       e->cmd.cmd);
	}
	return 0;
}

int main(void)
{
	struct ring_buffer *rb = NULL;
	struct bootstrap_bpf *skel;
	int err;

    // --- 타임스탬프 보정을 위한 오프셋 계산 ---
    struct timespec realtime_ts, monotonic_ts;
    clock_gettime(CLOCK_REALTIME, &realtime_ts);
    clock_gettime(CLOCK_MONOTONIC, &monotonic_ts);
    long long offset = (long long)realtime_ts.tv_sec * 1000000000 + realtime_ts.tv_nsec - 
                       ((long long)monotonic_ts.tv_sec * 1000000000 + monotonic_ts.tv_nsec);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = bootstrap_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	err = bootstrap_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = bootstrap_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	
    // ring_buffer__new에 오프셋 값을 컨텍스트로 전달합니다.
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, &offset, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	fprintf(stderr, "[ebpf-trace-monitor] Start monitoring (JSON output)...\n");
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	bootstrap_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}

