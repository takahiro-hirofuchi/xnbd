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




/* common with all sessions for a particular disk */
struct xnbd_info {
	/* local disk */
	char *diskpath;
	int diskfd;
	int diskopened;
	int readonly;

	/* local disk and remote disk */
	off_t disksize;
	// uint32_t nblocks;
	unsigned long nblocks;

	/* CoW */
	struct disk_stack *ds;
	int cow;


	/* listen port as a nbd server */
	int port;

	/* cache disk */
	char *cachepath;
	int cachefd;
	int cacheopened;

	/* cached bitmap file */
	char *cbitmappath;
	// int cbitmapopened;

	/* cached bitmap array (mmaped) */
	unsigned long *cbitmap;
	size_t cbitmaplen;

	/* remote nbd sever for caching */
	char *remotehost;
	char *remoteport;

	/* proxy mode */
	int proxymode;

	const char *bgctlprefix;

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







extern const unsigned int CBLOCKSIZE;
extern unsigned int PAGESIZE;



extern const unsigned long XNBD_BGCTL_MAGIC_CACHE_ALL;
extern const unsigned long XNBD_BGCTL_MAGIC_SHUTDOWN;










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

int proxy_server(struct xnbd_session *);
int target_server(struct xnbd_session *);
int target_server_cow(struct xnbd_session *);
struct disk_stack *open_cow_disk(char *diskpath, int newfile, int cowid);
void close_cow_disk(struct disk_stack *ds, int delete_cow);
#endif
