/*
 * xNBD - an enhanced Network Block Device program
 *
 * Copyright (C) 2008-2014 National Institute of Advanced Industrial Science
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

static inline unsigned long get_bindex_sta(const unsigned int blocksize, const off_t iofrom)
{
	return iofrom / blocksize;
}

static inline unsigned long get_bindex_end(const unsigned int blocksize, const off_t ioend)
{
	if (ioend % blocksize == 0)
		return ioend / blocksize - 1;
	else
		return ioend / blocksize;
}

char *get_line(int fd);
int put_line(int fd, const char *msg);

#include <pthread.h>
#include <signal.h>

void sigmask_all(void);

#include <poll.h>
int wait_until_readable(int fd, int unblock_fd);
void make_pipe(int *write_fd, int *read_fd);
void make_sockpair(int *fd0, int *fd1);

void *mmap_or_abort(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void munmap_or_abort(void *addr, size_t len);

struct mmap_region {
	void *mmap_buf; // internal
	size_t mmap_len; // internal

	void *iobuf; // points to iofrom
};

struct mmap_region *mmap_region_create(int fd, off_t iofrom, size_t iolen, int readonly);
void mmap_region_free(struct mmap_region *mpinfo);
void mmap_region_msync(struct mmap_region *mr);

#endif
