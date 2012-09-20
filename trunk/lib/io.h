/* 
 * xNBD - an enhanced Network Block Device program
 *
 * Copyright (C) 2008-2011 National Institute of Advanced Industrial Science
 * and Technology
 *
 * Author: Takahiro Hirofuchi <t.hirofuchi _at_ aist.go.jp>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307, USA.
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
#include <sys/mman.h>


void read_all(int fd, void *buf, size_t len);
void write_all(int fd, const void *buf, size_t len);
void dump_buffer(const char *buff, size_t bufflen);
void dump_buffer_all(const char *buff, size_t bufflen);

pthread_t pthread_create_or_abort(void * (*start_routine)(void *), void *arg);
pid_t fork_or_abort(void);

off_t get_disksize(int fd);
off_t get_disksize_of_path(const char *path);
void calc_block_index(const unsigned int blocksize, off_t iofrom, size_t iolen, unsigned long *index_start, unsigned long *index_end);

char *get_line(int fd);
int put_line(int fd, const char *msg);

#include <pthread.h>
#include <signal.h>

void sigmask_all(void);

#include <poll.h>
int wait_until_readable(int fd, int unblock_fd);
void make_pipe(int *write_fd, int *read_fd);
void make_sockpair(int *fd0, int *fd1);
int poll_data_and_event(int datafd, int event_listener_fd) __attribute__((deprecated));
void get_event_connecter(int *notifier, int *listener) __attribute__((deprecated));
void munmap_or_abort(void *addr, size_t len);
#endif
