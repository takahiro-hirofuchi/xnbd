/* 
 * xNBD - an enhanced Network Block Device program
 *
 * Copyright (C) 2008-2013 National Institute of Advanced Industrial Science
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

#ifndef XNBD_H
#define XNBD_H

/* automatically redefine fstat, lseek, and etc. for 64 bit */
#define _FILE_OFFSET_BITS 64

/* add for off64_t */
#define _LARGEFILE64_SOURCE

#define _GNU_SOURCE

#include "lib/xutils.h"




#include <inttypes.h>
#include <stdbool.h>

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>

#include <fcntl.h>

#include <sys/time.h>
#include <time.h>



/* mmap */
#include <sys/mman.h>

#include <sys/wait.h>

#define _GNU_SOURCE
#include <getopt.h>
#include <signal.h>

#include <stdio.h>
#include <syslog.h>
#include <string.h>

/* writev */
#include <sys/uio.h>

#include <pthread.h>


#include <glib.h>
#include <poll.h>


#ifdef XNBD_LZO
#include <lzo/lzoconf.h>
#include <lzo/lzo1x.h>
#endif


struct disk_image {
	char *path;
	// char path[PATH_MAX];
	int diskfd;

	// char bmpath[PATH_MAX];
	char *bmpath;
	// int bmfd;
	unsigned long *bm;
	size_t bmlen;
};

#define MAX_DISKIMAGESTACK 10
struct disk_stack {
	int nlayers;
	struct disk_image *image[MAX_DISKIMAGESTACK];

	off_t disksize;
};

struct disk_stack_io {
	struct disk_stack *ds;

	char *bufs[MAX_DISKIMAGESTACK];
	size_t buflen;
	struct iovec *iov;
	unsigned int iov_size;
};


struct disk_stack_io *disk_stack_mmap(struct disk_stack *ds, off_t iofrom, size_t iolen, int reading);
void free_disk_stack_io(struct disk_stack_io *io);


enum xnbd_cmd_type {
	xnbd_cmd_unknown = -1,
	xnbd_cmd_target = 0,
	xnbd_cmd_cow_target,
	xnbd_cmd_proxy,
	xnbd_cmd_help,
	xnbd_cmd_version,
};


/* common with all sessions for a particular disk */
struct xnbd_info {
	enum xnbd_cmd_type cmd;

	off_t disksize; /* size of the local/remote disk */
	unsigned long nblocks;
	int readonly;

	GList *sessions;

	/* xnbd_cmd_target mode */
	char *target_diskpath;
	int target_diskfd;

	/* xnbd_cmd_cow_target mode */
	char *cow_diskpath;
	struct disk_stack *cow_ds;

	/* xnbd_cmd_proxy mode */
	int proxy_pid;
	int proxy_sockpair_proxy_fd;  /* hold in the proxy server */
	int proxy_sockpair_master_fd; /* hold in the master server (NOTE) */
	/*
	 * NOTE: when invoking a new thread, must close the master_fds of the
	 * other sessions.
	 **/

	char *proxy_diskpath;   /* cache disk */
	char *proxy_bmpath; /* cached bitmap file */
	char *proxy_rhost;  /* remote nbd sever */
	char *proxy_rport;
	char *proxy_unixpath;
	char *proxy_target_exportname;  /* export name to request from a xnbd-wrapper target */
	bool proxy_clear_bitmap;

	unsigned long long max_queue_len_sum;
};



struct xnbd_session {
	int clientfd;       /* master and worker */
	struct xnbd_info *xnbd;

	int pipe_worker_fd; /* worker */
	int pipe_master_fd; /* master */
	pid_t pid;          /* master */
	int notifying;      /* master */
};







extern const unsigned int CBLOCKSIZE;
extern unsigned int PAGESIZE;



extern const unsigned long XNBD_BGCTL_MAGIC_CACHE_ALL;
extern const unsigned long XNBD_BGCTL_MAGIC_SHUTDOWN;



/* default XNBD server port */
extern const int XNBD_PORT;





struct mmap_partial {
	void *iobuf;

	void *buf;
	size_t len;
	off_t offset;
};

struct mmap_partial *mmap_partial_map(int fd, off_t iofrom, size_t iolen, int readonly);
void mmap_partial_unmap(struct mmap_partial *mpinfo);



#define DEFAULT_CACHESTAT_PATH "/tmp/xnbd_cachestat"
void cachestat_dump(char *path);
void cachestat_dump_loop(char *path, unsigned int);
void cachestat_cache_odread(void);
void cachestat_cache_odwrite(void);
void cachestat_cache_bgcopy(void);
void cachestat_read_block(void);
void cachestat_write_block(void);
void cachestat_miss(void);
void cachestat_hit(void);
int cachestat_initialize(const char *path, unsigned long blocks);
int cachestat_shutdown(void);




void get_io_range_index(off_t iofrom, size_t iolen, unsigned long *index_start, unsigned long *index_end);
void *mmap_iorange(struct xnbd_info *xnbd, int fd, off_t iofrom, size_t iolen, char **mmaped_buf, size_t *mmaped_len, off_t *mmaped_offset);
int poll_request_arrival(struct xnbd_session *ses);
void check_disksize(char *diskpath, off_t disksize);
unsigned long get_disk_nblocks(off_t disksize);


/* xnbd_cmd_target mode */
void xnbd_target_open_disk(char *diskpath, struct xnbd_info *xnbd);
void xnbd_target_make_snapshot(struct xnbd_info *xnbd);
int xnbd_target_session_server(struct xnbd_session *);

/* xnbd_cmd_cow_target mode */
struct disk_stack *xnbd_cow_target_open_disk(char *diskpath, int newfile, int cowid);
void xnbd_cow_target_close_disk(struct disk_stack *ds, int delete_cow);
int xnbd_cow_target_session_server(struct xnbd_session *);

/* xnbd_cmd_proxy mode */
void xnbd_proxy_start(struct xnbd_info *xnbd);
void xnbd_proxy_stop(struct xnbd_info *xnbd);
int xnbd_proxy_session_server(struct xnbd_session *ses);

#endif
