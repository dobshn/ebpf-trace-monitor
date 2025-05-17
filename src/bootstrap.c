// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "bootstrap.h"
#include "bootstrap.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
        /* TODO: 시간 출력 ISO 8601 포맷 */
	if (e->type == EVENT_EXEC) {
		printf("{\"type\": \"exec\", "
		       "\"timestamp\": %llu, "
		       "\"pid\": %d, "
		       "\"ppid\": %d, "
		       "\"comm\": \"%s\", "
		       "\"filename\": \"%s\"}\n",
		       e->timestamp,
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
		       e->timestamp,
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
		       e->timestamp,
		       e->pid,
		       e->ppid,
		       e->comm,
		       e->open.filename);
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct bootstrap_bpf *skel;
	int err;

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = bootstrap_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = bootstrap_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = bootstrap_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
	
	/* 모니터링 시작 */
	printf("[ebpf-trace-monitor] Start monitoring (JSON output)...\n");

	/* Process events */
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
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
	/* Clean up */
	ring_buffer__free(rb);
	bootstrap_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
