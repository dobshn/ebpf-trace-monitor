/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define TASK_COMM_LEN	 16
#define MAX_FILENAME_LEN 127

enum event_type {
        EVENT_EXEC,
        EVENT_EXIT
};

struct event {
        /* 공통 필드 */
        enum event_type type;
	int pid;
	int ppid;
	char comm[TASK_COMM_LEN];
	unsigned long long timestamp;
	
	/* 이벤트 별 특화 필드 */
	union {
	        struct {
	                char filename[MAX_FILENAME_LEN];
	        } exec;
	        
	        struct {
	                unsigned exit_code;
	                unsigned long long duration_ns;
	        } exit;
	};
};

#endif /* __BOOTSTRAP_H */
