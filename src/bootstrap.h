/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
/* Modified by dobshn, 2025 */
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define TASK_COMM_LEN	 16   /* 프로세스 이름(comm) 최대 길이 */
#define MAX_CMD_LEN      80   /* 쉘 커맨드 문자열 최대 길이 */
#define MAX_FILENAME_LEN 127  /* 파일 경로 최대 길이 */

/*
 * 이벤트 종류를 정의한다.
 * 각각의 이벤트는 event 구조체 내부에서 type 필드로 식별된다.
 */
enum event_type {
        EVENT_EXEC,   /* exec() 호출 */
        EVENT_EXIT,   /* 프로세스 종료 */
        EVENT_OPEN,   /* 파일 open() */
        EVENT_CONN,   /* TCP connect() */
        EVENT_CMD     /* Shell 명령어 실행 */
};

/*
 * 커널에서 사용자 공간으로 전달되는 이벤트 구조체.
 * 모든 이벤트는 공통 필드와 유형별 특화 필드로 구성된다.
 */
struct event {
        /* 공통 필드 */
        enum event_type type;         /* 이벤트 종류 */
	int pid;                      /* 이벤트 발생 프로세스의 PID */
	int ppid;                     /* 부모 프로세스의 PID */
	char comm[TASK_COMM_LEN];     /* 프로세스 이름 */
	unsigned long long timestamp; /* 이벤트 발생 시각 */
	
	/* 이벤트 별 특화 필드 */
	union {
	        struct {
	                char filename[MAX_FILENAME_LEN];  /* 실행한 프로그램의 경로 */
	        } exec;
	        
	        struct {
	                unsigned exit_code;               /* 프로세스 종료 코드 */
	                unsigned long long duration_ns;   /* 프로세스 실행 시간 (ns) */
	        } exit;
	        
	        struct {
	                char filename[MAX_FILENAME_LEN];  /* open 호출한 파일 경로 */
	        } open;
	        
	        struct {
	                __u32 saddr;  /* 출발지 IP 주소 (IPv4, network byte order) */
	                __u32 daddr;  /* 목적지 IP 주소 (IPv4, network byte order) */
	                __u16 dport;  /* 목적지 포트 번호 (host byte order) */
	        } conn;
	        
	        struct {
	                char cmd[MAX_CMD_LEN];  /* 사용자가 입력한 shell 명령 */
	        } cmd;
	};
};

#endif /* __BOOTSTRAP_H */
