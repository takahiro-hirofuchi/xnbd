/*
 * partially excerpted and modified from usbip.
 *
 * Copyright (C) 2005-2008 Takahiro Hirofuchi
 * Copyright (C) 2008-2010 National Institute of Advanced Industrial Science and Technology
 *
 * Author: Takahiro Hirofuchi
 */
#ifndef LIB_XNBD_IO_H
#define LIB_XNBD_IO_H

#include "common.h"
#include "net.h"
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>


void read_all(int fd, void *buf, size_t len);
void write_all(int fd, void *buf, size_t len);
void dump_buffer(const char *buff, size_t bufflen);
void dump_buffer_all(const char *buff, size_t bufflen);

pthread_t pthread_create_or_abort(void * (*start_routine)(void *), void *arg);
pid_t fork_or_abort(void);

off_t get_disksize(int fd);
off_t get_disksize_of_path(char *path);
void calc_block_index(const unsigned int blocksize, off_t iofrom, size_t iolen, unsigned long *index_start, unsigned long *index_end);

char *get_line(int fd);
int put_line(int fd, const char *msg);

#include <pthread.h>
#include <signal.h>

void sigmask_all(void);

#include <poll.h>
int poll_data_and_event(int datafd, int event_listener_fd);
void get_event_connecter(int *notifier, int *listener);
#endif
