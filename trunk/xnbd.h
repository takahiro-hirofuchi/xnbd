/* 
 * Copyright (C) 2008-2009 National Institute of Advanced Industrial Science and Technology
 */
#ifndef XNBD_H
#define XNBD_H

/* automatically redefine fstat, lseek, and etc. for 64 bit */
#define _FILE_OFFSET_BITS 64

/* add for off64_t */
#define _LARGEFILE64_SOURCE

#define _GNU_SOURCE

#include <xutils.h>




#include <inttypes.h>

#include <unistd.h>
#include <strings.h>
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




struct disk_image {
	char *path;
	int diskfd;

	char bmpath[PATH_MAX];
	int bmfd;
	uint32_t *bm;
	int bmlen;
};

#define MAX_DISKIMAGESTACK 10
struct disk_stack {
	int nlayers;
	struct disk_image *image[MAX_DISKIMAGESTACK];

	uint64_t disksize;


};

struct disk_stack_io {
	struct disk_stack *ds;

	char *bufs[MAX_DISKIMAGESTACK];
	uint32_t buflen;
	struct iovec *iov;
	int iov_size;
};





/* common with all sessions for a particular disk */
struct xnbd_info {
	/* local disk */
	char *diskpath;
	int diskfd;
	int diskopened;
	int readonly;

	/* local disk and remote disk */
	uint64_t disksize;
	uint32_t nblocks;

	/* CoW */
	struct disk_stack *ds;
	int cow;
	char *cowpath;


	/* listen port as a nbd server */
	int port;

	/* cache disk */
	char *cachepath;
	int cachefd;
	int cacheopened;

	/* cached bitmap file */
	char *cbitmappath;
	int cbitmapfd;
	int cbitmapopened;

	/* cached bitmap array (mmaped) */
	uint32_t *cbitmap;
	int cbitmaplen;

	/* remote nbd sever for caching */
	char *remotehost;
	char *remoteport;

	/* proxy mode */
	int proxymode;

	char *bgctlprefix;

	GList *sessions;
};



struct xnbd_session {
	/* client socket for which xnbd peforms a nbd server */
	int clientfd;

	int remotefd;

	int event_listener_fd;

	struct xnbd_info *xnbd;


	/* valid in master */
	pid_t pid;
	int event_notifier_fd;

	int notifying;
};







extern const uint32_t CBLOCKSIZE;
extern unsigned int PAGESIZE;










void get_io_range_index(uint64_t iofrom, uint32_t iolen, uint32_t *index_start, uint32_t *index_end);






#define DEFAULT_CACHESTAT_PATH "/tmp/xnbd_cachestat"
void cachestat_dump(char *path);
void cachestat_dump_loop(char *path, int);
void cachestat_cache_odread(void);
void cachestat_cache_odwrite(void);
void cachestat_cache_bgcopy(void);
void cachestat_read_block(void);
void cachestat_write_block(void);
void cachestat_miss(void);
void cachestat_hit(void);
int cachestat_initialize(char *path, uint32_t blocks);
int cachestat_shutdown(void);




void *mmap_iorange(struct xnbd_info *xnbd, int fd, uint64_t iofrom, uint32_t iolen, char **mmaped_buf, uint32_t *mmaped_len, uint64_t *mmaped_offset);
int poll_request_arrival(struct xnbd_session *ses);
void check_disksize(char *diskpath, uint64_t disksize);

int proxy_server(struct xnbd_session *);
int target_server(struct xnbd_session *);
int target_server_cow(struct xnbd_session *);
void setup_cow_disk(char *diskpath, struct xnbd_info *xnbd);
void destroy_disk_stack(struct disk_stack *ds);
#endif
