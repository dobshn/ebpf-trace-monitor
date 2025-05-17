/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define TASK_COMM_LEN	 16
#define MAX_CMD_LEN      80
#define MAX_FILENAME_LEN 127

enum event_type {
        EVENT_EXEC,
        EVENT_EXIT,
        EVENT_OPEN,
        EVENT_CONN,
        EVENT_CMD
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
	        
	        struct {
	                char filename[MAX_FILENAME_LEN];
	        } open;
	        
	        struct {
	                __u32 saddr;
	                __u32 daddr;
	                __u16 dport;
	        } conn;
	        
	        struct {
	                char cmd[MAX_CMD_LEN];
	        } cmd;
	};
};

#endif /* __BOOTSTRAP_H */
