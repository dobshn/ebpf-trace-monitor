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

/*
 * 종료 시그널(SIGINT, SIGTERM) 수신 시 종료 플래그를 설정한다.
 * 메인 루프는 이 플래그를 감지하여 종료한다.
 */
static void sig_handler(int sig)
{
	exiting = true;
}

/*
 * TODO: 시간 출력 ISO 8601 포맷으로 변경
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
        /*
         * 각 이벤트 별로 특화된 정보를 포함하여 JSON 형식으로 출력한다.
         * 모든 이벤트가 공통으로 출력하는 항목은 다음과 같다.
         * - 이벤트 종류 (type)
         * - 이벤트 발생 시간 (timestamp)
         * - 프로세스 ID (pid)
         * - 부모 프로세스 ID (ppid)
         * - 프로세스 이름 (comm)
         */
	const struct event *e = data;
	/*
	 * 프로세스 생성 이벤트 정보를 출력한다.
	 */
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
	/*
	 * 프로세스 종료 이벤트 정보를 출력한다.
	 */
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
	/*
	 * 파일 오픈 이벤트 정보를 출력한다.
	 */
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
	/*
	 * TCP 연결 이벤트 정보를 출력한다.
	 */
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
		       e->timestamp,
		       e->pid,
		       e->ppid,
		       e->comm,
		       saddr_str,
		       daddr_str,
		       e->conn.dport);
	/*
	 * Shell 커맨드 입력 이벤트 정보를 출력한다.
	 */
	} else if (e->type == EVENT_CMD) {
		printf("{\"type\": \"cmd\", "
		       "\"timestamp\": %llu, "
		       "\"pid\": %d, "
		       "\"ppid\": %d, "
		       "\"comm\": \"%s\", "
		       "\"cmd\": \"%s\"}\n",
		       e->timestamp,
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

	/*
	 * Ctrl-C 시그널에 대한 시그널 핸들러를 지정한다.
	 * 프로세스 정상 종료 신호에 대한 시그널 핸들러도 지정한다.
	 */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	/*
	 * BPF 오브젝트 파일을 메모리에 로드한다.
	 * 실패시, skel == NULL이 되어 오류 메시지를 출력한 뒤
	 * 1을 반환하며 프로그램을 종료한다.
	 */
	skel = bootstrap_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}
	/*
         * BPF 오브젝트 파일을 커널에 로드된다.
         * 이때 verifier가 실행되어 검증이 진행된다.
         * 실패할 경우 0이 아닌 값을 반환한다.
         * skel 객체가 열려있기 때문에, cleanup으로 분기하여 종료한다.
         */
	err = bootstrap_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
	/*
         * 각 BPF 섹션을 tracepoint, kprobe, uprobe 등으로 attach한다.
         * 실패시 cleanup으로 분기하여 종료한다.
         */
	err = bootstrap_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	/*
	 * Ring buffer를 초기화 한다.
	 * 반환 값은 map의 파일 서술자가 된다.
	 */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
	/*
	 * 모니터링을 시작한다.
	 */
	printf("[ebpf-trace-monitor] Start monitoring (JSON output)...\n");
	while (!exiting) {
	        /*
	         * Ring buffer에서 이벤트를 기다린다.
	         * 이벤트 발생 시 handle_event()를 호출한다.
	         * 반환 값은 읽은 이벤트 수 또는 오류 코드가 된다.
	         */
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
	/*
	 * 리소스를 정리하고 프로그램을 종료한다.
	 */
	ring_buffer__free(rb);
	bootstrap_bpf__destroy(skel);
        /*
         * 실패 시, 에러코드를 양수로 변환한 뒤 반환한다.
         * libbpf 함수들은 실패 시 음수 에러코드를 반환하기 때문이다.
         * 성공 시, 0을 반환한다.
         */
	return err < 0 ? -err : 0;
}
