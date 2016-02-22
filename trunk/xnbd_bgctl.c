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

#include "xnbd_proxy.h"
#include <assert.h>
#include <sys/ioctl.h>
#include <math.h> /* floor() */



struct _SizedAsyncQueue {
	GMutex mutex;
	GCond  cond_pop;  // pop-able
	GCond  cond_push; // push-able
	GQueue queue;

	size_t max_size;
	size_t size;
};

typedef struct _SizedAsyncQueue SizedAsyncQueue;

SizedAsyncQueue *sized_async_queue_new(size_t max_size)
{
	SizedAsyncQueue* q = g_new(SizedAsyncQueue, 1);

	g_mutex_init(&q->mutex);
	g_cond_init(&q->cond_pop);
	g_cond_init(&q->cond_push);
	g_queue_init(&q->queue);

	q->max_size = max_size;
	q->size = 0;

	return q;
}

void sized_async_queue_push(SizedAsyncQueue *q, void *data)
{
	g_return_if_fail(q);
	g_return_if_fail(data);

	g_mutex_lock(&q->mutex);
	{
		while (!(q->size < q->max_size)) {
			g_cond_wait(&q->cond_push, &q->mutex);
		}

		// g_message("%zu < %zu", q->size, q->max_size);

		g_queue_push_head(&q->queue, data);
		q->size += 1;

		g_cond_signal(&q->cond_pop);
	}
	g_mutex_unlock(&q->mutex);
}

void *sized_async_queue_pop(SizedAsyncQueue *q)
{
	void *data;

	g_return_val_if_fail(q, NULL);

	g_mutex_lock(&q->mutex);
	{
		/* must check queue is poppable */
		while (!g_queue_peek_tail_link(&q->queue)) {
			g_cond_wait(&q->cond_pop, &q->mutex);
		}

		data = g_queue_pop_tail(&q->queue);
		g_assert(data);

		q->size -= 1;
		if (q->size < q->max_size) {
			g_cond_signal(&q->cond_push);
		}
	}
	g_mutex_unlock(&q->mutex);

	return data;
}

void sized_async_queue_destroy(SizedAsyncQueue *q)
{
	g_return_if_fail(q);

	if (q->size)
		warn("destroy a queue with data");

	g_mutex_clear(&q->mutex);
	g_cond_clear(&q->cond_pop);
	g_cond_clear(&q->cond_push);
	g_queue_clear(&q->queue);

	g_free(q);
}




struct progress_info {
	bool enabled;

	unsigned long blocks_total;
	unsigned long blocks_from_cache;
	unsigned long blocks_from_remote;

	unsigned int prev_cells_from_cache;
	unsigned int prev_cells_from_remote;
	unsigned int prev_int_percent;
};


struct xnbd_proxy_query *create_proxy_query(char *unix_path)
{
	int fd = unix_connect(unix_path);

	enum xnbd_proxy_cmd_type cmd = XNBD_PROXY_CMD_QUERY_STATUS;
	net_send_all_or_abort(fd, &cmd, sizeof(cmd));

	struct xnbd_proxy_query *query = g_malloc(sizeof(struct xnbd_proxy_query));
	net_recv_all_or_abort(fd, query, sizeof(*query));

	close(fd);

	return query;
}

void reconnect(char *unix_path, char *rhost, char *rport, const char *exportname)
{
	int fd = unix_connect(unix_path);

	int fwd_fd = net_connect(rhost, rport, SOCK_STREAM, IPPROTO_TCP);

	int ret;
	if (exportname)
		ret = nbd_negotiate_with_server_new(fwd_fd, NULL, NULL, strlen(exportname), exportname);
	else
		ret = nbd_negotiate_with_server(fwd_fd, NULL, NULL);

	if (ret)
		err("negotiation failed");


	enum xnbd_proxy_cmd_type cmd = XNBD_PROXY_CMD_REGISTER_FORWARDER_FD;
	net_send_all_or_abort(fd, &cmd, sizeof(cmd));
	unix_send_fd(fd, fwd_fd);

	close(fd);
}


void start_register_fd(char *unix_path, int *fd_ret, int *ctl_fd_ret)
{
	int fd = unix_connect(unix_path);

	int ctl_fd, proxy_fd;
	make_sockpair(&ctl_fd, &proxy_fd);

	enum xnbd_proxy_cmd_type cmd = XNBD_PROXY_CMD_REGISTER_FD;
	net_send_all_or_abort(fd, &cmd, sizeof(cmd));
	unix_send_fd(fd, proxy_fd);
	close(proxy_fd);

	*fd_ret = fd;
	*ctl_fd_ret = ctl_fd;
}

void end_register_fd(int fd, int ctl_fd)
{
	nbd_client_send_disc_request(ctl_fd);
	close(ctl_fd);

	/* make sure this session is cleaned up in xnbd_proxy */
	char buf[1];
	net_recv_all_or_abort(fd, buf, 1);

	close(fd);
}

void *setup_shared_buffer(char *unix_path)
{
	char tmppath[] = "/tmp/xnbd-proxy-shared-buffer.XXXXXX";
	size_t len = XNBD_SHARED_BUFF_SIZE;

	int buf_fd = mkstemp(tmppath);
	if (buf_fd < 0)
		err("mkstemp, %m");

	unlink(tmppath);

	int ret = ftruncate(buf_fd, len);
	if (ret < 0)
		err("ftruncate, %m");

	void *shared_buff = mmap(NULL, len, PROT_WRITE, MAP_SHARED, buf_fd, 0);
	if (shared_buff == MAP_FAILED)
		err("mmap, %m");

	info("shared buffer allocated, %p (len %zu)", shared_buff, len);

	/* send buf_fd */
	int unix_fd = unix_connect(unix_path);
	enum xnbd_proxy_cmd_type cmd = XNBD_PROXY_CMD_REGISTER_SHARED_BUFFER_FD;
	net_send_all_or_abort(unix_fd, &cmd, sizeof(cmd));
	unix_send_fd(unix_fd, buf_fd);
	close(unix_fd);


	close(buf_fd);

	return shared_buff;
}

void close_shared_buffer(void *shared_buff)
{
	size_t len = XNBD_SHARED_BUFF_SIZE;
	munmap_or_abort(shared_buff, len);
	info("shared buffer deallocated, %p (len %zu)", shared_buff, len);
}

void cache_block_range(char *unix_path, unsigned long *bm, off_t disksize, int remote_fd, char *shared_buff)
{
	int ctl_fd, unix_fd;
	unsigned long disk_nblocks = get_disk_nblocks(disksize);
	start_register_fd(unix_path, &unix_fd, &ctl_fd);


	for (unsigned long index = 0; index < disk_nblocks; index += XNBD_SHARED_BUFF_NBLOCKS) {
		unsigned long nblocks = XNBD_SHARED_BUFF_NBLOCKS;
		if (disk_nblocks - index < XNBD_SHARED_BUFF_NBLOCKS)
			nblocks = disk_nblocks - index;

		int all_cached = 1;
		for (unsigned long i = index; i < index + nblocks; i++) {
			if (!bitmap_test(bm, i)) {
				all_cached = 0;
				break;
			}
		}

		if (all_cached)
			continue;

		off_t iofrom = (off_t) index * CBLOCKSIZE;
		size_t iolen = (size_t) nblocks * CBLOCKSIZE;
		iolen = confine_iolen_within_disk(disksize, iofrom, iolen);

		int ret = nbd_client_send_read_request(remote_fd, iofrom, iolen);
		if (ret < 0)
			err("send_read_request, %m");

		ret = nbd_client_recv_read_reply(remote_fd, shared_buff, iolen);
		if (ret < 0)
			err("recv_read_reply, %m");

		xnbd_proxy_control_cache_block(ctl_fd, disksize, index, nblocks);
	}


	end_register_fd(unix_fd, ctl_fd);
}

void cache_all_blocks_with_dedicated_connection(char *unix_path, unsigned long *bm, struct xnbd_proxy_query *query)
{
	int remote_fd = net_connect(query->rhost, query->rport, SOCK_STREAM, IPPROTO_TCP);
	if (remote_fd < 0)
		err("connect, %m");

	off_t remote_disksize;
	int ret = nbd_negotiate_with_server(remote_fd, &remote_disksize, NULL);
	if (ret < 0)
		err("negotiation failed");
	if (remote_disksize != query->disksize)
		err("disksize mismatch");


	char *shared_buff = setup_shared_buffer(unix_path);

	cache_block_range(unix_path, bm, query->disksize, remote_fd, shared_buff);

	close_shared_buffer(shared_buff);

	nbd_client_send_disc_request(remote_fd);
	close(remote_fd);
}


struct cache_rx_ctl {
	int ctl_fd;
	SizedAsyncQueue *q;

	unsigned long nblocks;
	bool progress_enabled;
};

char cache_rx_req_eof;
char cache_rx_req_remote_first;
char cache_rx_req_remote_later;
char cache_rx_req_cached;

struct progress_info *progress_setup(unsigned long nblocks);
void progress_refresh_draw(struct progress_info *p);

void *cache_all_blocks_receiver_main(void *arg)
{
	struct cache_rx_ctl *cache_rx = (struct cache_rx_ctl *) arg;

	set_process_name("cache_rx");
	block_all_signals();
	info("create cache_rx thread");

	struct progress_info *progress = progress_setup(cache_rx->nblocks);
	progress->enabled = cache_rx->progress_enabled;
	progress_refresh_draw(progress);

	for (;;) {
		char *data = sized_async_queue_pop(cache_rx->q);

		if (data == &cache_rx_req_eof)
			break;
		else if (data == &cache_rx_req_remote_first) {
			int ret = nbd_client_recv_reply_header(cache_rx->ctl_fd, UINT64_MAX);
			if (ret < 0)
				err("recv header, %m");
			progress->blocks_from_remote += 1;
		} else if (data == &cache_rx_req_remote_later) {
			progress->blocks_from_remote += 1;
		} else {
			progress->blocks_from_cache += 1;
		}
		progress_refresh_draw(progress);
	}

	g_free(progress);

	info("done cache_rx thread");

	return NULL;
}


void refresh_progress(struct progress_info * p_progress, unsigned int columns)
{
	const unsigned int overhead = 3 + 3 + 1; /* <percent> + "% [" + "]" */

	if (columns < overhead + 1) {
		/* Terminal too small */
		return;
	}


	assert(p_progress);
	assert(p_progress->blocks_from_remote <= p_progress->blocks_total);
	assert(p_progress->blocks_from_cache <= p_progress->blocks_total);
	const unsigned long blocks_processed = p_progress->blocks_from_cache + p_progress->blocks_from_remote;
	assert(blocks_processed <= p_progress->blocks_total);

	/* Handle int cast rounding trouble */
	const double double_percent = blocks_processed / (double)p_progress->blocks_total * 100.0;
	unsigned int int_percent = (unsigned int)double_percent;
	if ((double_percent > 0.0) && (double_percent < 1.0)) {
		int_percent = 1;
	} else if ((double_percent > 99.0) && (double_percent < 100.0)) {
		int_percent = 99;
	}

	const unsigned int cells_total = columns - overhead;
	unsigned int cells_from_remote = (unsigned int)(p_progress->blocks_from_remote / (double)p_progress->blocks_total * cells_total);
	unsigned int cells_from_cache = (unsigned int)(p_progress->blocks_from_cache / (double)p_progress->blocks_total * cells_total);
	const unsigned int cells_from_anywhere = (unsigned int)(blocks_processed / (double)p_progress->blocks_total * cells_total);

	/* Make sure that integer division does not make the bar appear too short */
	if (cells_from_cache + cells_from_remote < cells_from_anywhere) {
		cells_from_remote = cells_from_anywhere - cells_from_cache;
	}
	assert(cells_from_cache + cells_from_remote <= cells_total);

	/* Steal space for moving arrow '>' */
	if (cells_from_cache > 0) {
		cells_from_cache--;
	} else if (cells_from_remote > 0) {
		cells_from_remote--;
	}

	if ((cells_from_cache == p_progress->prev_cells_from_cache)
			&& (cells_from_remote == p_progress->prev_cells_from_remote)
			&& (int_percent == p_progress->prev_int_percent)
			&& (blocks_processed != 0)
			&& (blocks_processed != p_progress->blocks_total)) {
		/* Save printing same bar again, big speed up */
		return;
	}


	/* Draw into buffer */
	char progress_bar[cells_total + 1];
	unsigned int array_u = 0;
	unsigned int u;

	for (u = 0; u < cells_from_cache; u++) {
		progress_bar[array_u++] = '+';
	}
	for (u = 0; u < cells_from_remote; u++) {
		progress_bar[array_u++] = '=';
	}

	progress_bar[array_u++] = '>';

	const unsigned int cells_blank = cells_total - (cells_from_cache + cells_from_remote + 1);
	for (u = 0; u < cells_blank; u++) {
		progress_bar[array_u++] = ' ';
	}

	progress_bar[array_u++] = '\0';


	/* Flush buffer to screen */
	FILE * const target = stderr;
	fprintf(target, "\r%3d%% [%s]%s", int_percent, progress_bar,
		   (blocks_processed == p_progress->blocks_total) ? "\n" : "");
	fflush(target);


	p_progress->prev_cells_from_cache = cells_from_cache;
	p_progress->prev_cells_from_remote = cells_from_remote;
	p_progress->prev_int_percent = int_percent;
}

unsigned short int get_column_widths(void)
{
	struct winsize terminal_size;
	int ret = ioctl(STDOUT_FILENO, TIOCGWINSZ, &terminal_size);
	if (ret < 0) {
		err("ioctl TIOCGWINSZ, %m");
		return 0;
	}

	return terminal_size.ws_col;
}

struct progress_info *progress_setup(unsigned long nblocks)
{
	struct progress_info *p = g_malloc0(sizeof(struct progress_info));
	p->blocks_total = nblocks;

	return p;
}

void progress_refresh_draw(struct progress_info *p)
{
	if (p->enabled)
		refresh_progress(p, get_column_widths());
}


/*
 * The below parameters effects performance of the --cache-all operation.
 * BLOCKS_AT_ONCE is the number of blocks that are to be cached in one request.
 * ASYNC_DEPTH is the number of requests that are to be enqueued
 * asynchronously.
 *
 * Migrate a Xen guest with a 30 GiB hard disk.
 * BLOCK_AT_ONCE is set to 31.
 *
 *    ASYNC_DEPTH
 *    |      Duration approximate (minutes)
 *    |      |  Duration exact
 *    -----------------------------------
 *    1     14  0:13:57.739573
 *    1     12  0:11:35.063002    (* BLOCKS_AT_ONCE is set to 31000)
 *    10     9  0:09:06.786810
 *    100    6  0:05:57.978245
 *    1000   5  0:05:02.546333
 *    10000  5  0:04:59.861427
 *
 * Buffer and queue size limits were not nearly exceeded even during the 10k
 * run.
 *
 * So, for ASYNC_DEPTH * BLOCKS_AT_ONCE = 31000, we have
 *
 *    ASYNC_DEPTH
 *    |         BLOCKS_AT_ONCE
 *    |         |    Duration approximate (minutes)
 *    ---------------------------------------------
 *    1     31000   12
 *    1000     31    5
 *
 * (BLOCK_AT_ONCE=31 and ASYNC_DEPTH=1000) seems a good choice.
 *
 *
 * xnbd-server will accept any number of blocks in one request. But, other NBD
 * programs may have the limitation on the maximum number of blocks in one
 * request.
 *
 * Try 31 for BLOCK_AT_ONCE. It will be a safe choice.
 * CBLOCKSIZE (i.e., 4096 in default) * 32 = 128KB.
 */
#define XNBD_BGCTL_DEFAULT_BLOCKS_AT_ONCE 31
#define XNBD_BGCTL_DEFAULT_ASYNC_DEPTH 1000


void cache_all_blocks_async(char *unix_path, unsigned long *bm, off_t disksize, bool progress_enabled, unsigned long blocks_at_once)
{
	int unix_fd, ctl_fd;
	start_register_fd(unix_path, &unix_fd, &ctl_fd);
	unsigned long nblocks = get_disk_nblocks(disksize);

	struct cache_rx_ctl cache_rx;
	cache_rx.ctl_fd  = ctl_fd;
	cache_rx.q       = sized_async_queue_new(XNBD_BGCTL_DEFAULT_ASYNC_DEPTH);
	cache_rx.nblocks = nblocks;
	cache_rx.progress_enabled = progress_enabled;

	pthread_t cache_rx_tid = pthread_create_or_abort(cache_all_blocks_receiver_main, &cache_rx);

	info("requesting transfer of up to %lu blocks at once", blocks_at_once);

	for (unsigned long index = 0; index < nblocks; index += blocks_at_once) {
		unsigned long const AFTER_LAST_MAX = MIN(index + blocks_at_once, nblocks);

		unsigned long first = index;
		unsigned long after_last;  /* initialized in loop body further down */

		while (first < AFTER_LAST_MAX) {
			/* Make <after_last> point after last uncached block (with no cached blocks in between) */
			for (after_last = first; !bitmap_test(bm, after_last) && (after_last < AFTER_LAST_MAX); after_last++);

			/* At least a single block to fetch? */
			if (after_last > first) {
				dbg("blocks %lu to %lu (%lu in total): requesting transfer", first, after_last, after_last - first);

				off_t iofrom = (off_t) first * CBLOCKSIZE;
				size_t iolen = (off_t)(after_last - first) * CBLOCKSIZE;
				iolen = confine_iolen_within_disk(disksize, iofrom, iolen);

				int ret = nbd_client_send_request_header(ctl_fd, NBD_CMD_CACHE, iofrom, iolen, (UINT64_MAX));
				if (ret < 0) {
					err("send_read_request, %m");
				}

				/* Account for requested blocks */
				for (unsigned long i = first; i < after_last; i++) {
					if (i == first) {
						sized_async_queue_push(cache_rx.q, &cache_rx_req_remote_first);
					} else {
						sized_async_queue_push(cache_rx.q, &cache_rx_req_remote_later);
					}
				}
			}

			/* Make <first> point after last cached block (with no uncached blocks in between) */
			for (first = after_last; bitmap_test(bm, first) && (first < AFTER_LAST_MAX); first++);

			/* Account for skipped blocks */
			if (first > after_last) {
				dbg("blocks %lu to %lu (%lu in total): skipping, already cached", after_last, first, first - after_last);

				for (unsigned long i = after_last; i < first; i++) {
					sized_async_queue_push(cache_rx.q, &cache_rx_req_cached);
				}
			}
		}
	}


	sized_async_queue_push(cache_rx.q, &cache_rx_req_eof);
	pthread_join(cache_rx_tid, NULL);
	sized_async_queue_destroy(cache_rx.q);

	end_register_fd(unix_fd, ctl_fd);
}



void cache_all_blocks(char *unix_path, unsigned long *bm, off_t disksize)
{
	int unix_fd, ctl_fd;
	unsigned long nblocks = get_disk_nblocks(disksize);
	start_register_fd(unix_path, &unix_fd, &ctl_fd);

	for (unsigned long index = 0; index < nblocks; index++) {
		if (!bitmap_test(bm, index)) {
			xnbd_proxy_control_cache_block(ctl_fd, disksize, index, 1);
		}
	}

	end_register_fd(unix_fd, ctl_fd);
}

static struct option longopts[] = {
	/* commands */
	{"query",               no_argument, NULL, 'q'},
	{"switch",              no_argument, NULL, 's'},
	{"shutdown",            no_argument, NULL, 's'}, /* deprecated in favor of --switch */
	{"cache-all",           no_argument, NULL, 'c'},
	{"cache-all2",          no_argument, NULL, 'C'},
	{"reconnect",           no_argument, NULL, 'r'},
	{"help",                no_argument, NULL, 'h'},
	{"exportname",          required_argument, NULL, 'n'},
	{"blocks-per-request",  required_argument, NULL, 'k'},
	{"progress",            no_argument, NULL, 'p'},
	{"force",               no_argument, NULL, 'f'},
	{NULL, 0, NULL, 0},
};

#define HELP_STRING_FORMAT "\
Usage:\n\
  xnbd-bgctl                     --query      CONTROL_UNIX_SOCKET\n\
  xnbd-bgctl [--force]           --switch     CONTROL_UNIX_SOCKET\n\
  xnbd-bgctl [--progress] [--blocks-per-request COUNT]\n\
                                 --cache-all  CONTROL_UNIX_SOCKET\n\
  xnbd-bgctl                     --cache-all2 CONTROL_UNIX_SOCKET\n\
  xnbd-bgctl [--exportname NAME] --reconnect  CONTROL_UNIX_SOCKET REMOTE_HOST REMOTE_PORT\n\
\n\
Commands:\n\
  --query       query current status of the proxy mode\n\
  --cache-all   cache all blocks\n\
  --cache-all2  cache all blocks with the background connection (not yet implemented)\n\
  --switch      stop the proxy mode and restart the target mode\n\
  --reconnect   reconnect the forwarding session\n\
 (--shutdown)   alias to --switch, deprecated\n\
\n\
Options:\n\
  --exportname NAME           reconnect to a given image\n\
  --progress                  show a progress bar on stderr (default: disabled)\n\
  --blocks-per-request COUNT  request up to COUNT blocks at once (default: %d blocks)\n\
  --force                     force switch even if all blocks are not cached (default: disabled)\n\
\n\
"


void show_help_and_exit(const char *msg)
{
	if (msg)
		info("%s\n", msg);

	fprintf(stderr, HELP_STRING_FORMAT, XNBD_BGCTL_DEFAULT_BLOCKS_AT_ONCE);
	exit(msg ? EXIT_FAILURE : EXIT_SUCCESS);
}

static int start_monitor_connection(char *unix_path)
{
	int fd = unix_connect(unix_path);

	enum xnbd_proxy_cmd_type cmd = XNBD_PROXY_CMD_DETECT_SWITCH;
	net_send_all_or_abort(fd, &cmd, sizeof(cmd));

	return fd;
}

static void wait_for_target_mode(int monitor_fd) {
	char buf;
	int ret;

	info("waiting for switch to finish...");

	/* wait for disconnection by server */
	ret = recv(monitor_fd, &buf, 1, 0);
	/* expected value is 0 */
	if (ret != 0)
		warn("recv() returned unexpected value %d", ret);
	close(monitor_fd);
}

int main(int argc, char **argv)
{
	enum xnbd_bgctl_cmd_type {
		xnbd_bgctl_cmd_unknown,
		xnbd_bgctl_cmd_query,
		xnbd_bgctl_cmd_cache_all,
		xnbd_bgctl_cmd_cache_all2,
		xnbd_bgctl_cmd_switch,
		xnbd_bgctl_cmd_reconnect,
	} cmd = xnbd_bgctl_cmd_unknown;

	const char *exportname = NULL;
	bool progress_enabled = false;
	bool force_enabled = false;
	unsigned long blocks_at_once = XNBD_BGCTL_DEFAULT_BLOCKS_AT_ONCE;

	for (;;) {
		int c;
		int index = 0;

		c = getopt_long(argc, argv, "qscCr", longopts, &index);
		if (c == -1) /* all options were parsed */
			break;

		switch (c) {
			case 'q':
				if (cmd != xnbd_bgctl_cmd_unknown)
					show_help_and_exit("specify one mode");

				cmd = xnbd_bgctl_cmd_query;
				break;

			case 's':
				if (cmd != xnbd_bgctl_cmd_unknown)
					show_help_and_exit("specify one mode");

				cmd = xnbd_bgctl_cmd_switch;
				break;

			case 'c':
				if (cmd != xnbd_bgctl_cmd_unknown)
					show_help_and_exit("specify one mode");

				cmd = xnbd_bgctl_cmd_cache_all;
				break;

			case 'C':
				if (cmd != xnbd_bgctl_cmd_unknown)
					show_help_and_exit("specify one mode");

				cmd = xnbd_bgctl_cmd_cache_all2;
				break;

			case 'r':
				if (cmd != xnbd_bgctl_cmd_unknown)
					show_help_and_exit("specify one mode");

				cmd = xnbd_bgctl_cmd_reconnect;
				break;

			case 'h':
				show_help_and_exit(NULL);
				break;

			case 'n':
				exportname = optarg;
				break;

			case '?':
				show_help_and_exit("unknown option");
				break;

			case 'k':
				blocks_at_once = atol(optarg);
				if (blocks_at_once <= 0)
					show_help_and_exit("block count must be greater than zero");
				break;

			case 'p':
				progress_enabled = true;
				break;

			case 'f':
				force_enabled = true;
				break;

			default:
				err("getopt");
		}
	}

	char *unix_path = NULL;
	char *rhost = NULL;
	char *rport = NULL;


	switch (cmd) {
		case xnbd_bgctl_cmd_reconnect:
			if (argc - optind == 3) {
				unix_path = argv[optind];
				rhost = argv[optind + 1];
				rport = argv[optind + 2];
			} else
				show_help_and_exit("invalid arguments");

			break;

		case xnbd_bgctl_cmd_cache_all:
		case xnbd_bgctl_cmd_cache_all2:
		case xnbd_bgctl_cmd_switch:
		case xnbd_bgctl_cmd_query:
		case xnbd_bgctl_cmd_unknown:
			if (argc - optind == 1)
				unix_path = argv[optind];
			else
				show_help_and_exit("specify a control socket file");
	}


	if (exportname && cmd != xnbd_bgctl_cmd_reconnect)
		warn("ignore --exportname");
	if (force_enabled && cmd != xnbd_bgctl_cmd_switch)
		warn("ignore --force");
	if (progress_enabled)
		if (cmd != xnbd_bgctl_cmd_cache_all && cmd != xnbd_bgctl_cmd_cache_all2)
			warn("ignore --progress");


	size_t bmlen;

	struct xnbd_proxy_query *query = create_proxy_query(unix_path);
	unsigned long nblocks = get_disk_nblocks(query->disksize);
	unsigned long *bm = bitmap_open_file(query->bmpath, nblocks, &bmlen, 1, 0);
	unsigned long cached = bitmap_popcount(bm, nblocks);

	/* Prevent printf from displaying "100.0%" before it's actually 100% (issue #12) */
	double percent_cached = nblocks ? (100.0L * cached / nblocks) : 0.0L; /* do not divide it by zero */
	percent_cached = floor(percent_cached * 10) / 10;

	info("%s (%s): disksize %ju", query->diskpath, query->bmpath, query->disksize);
	info("forwarded to %s:%s", query->rhost, query->rport);
	info("cached blocks %lu / %lu (%.1f%%)", cached, nblocks, percent_cached);
	info("internal buffer usage: %zu bytes / %zu bytes (%.1f%%)", query->cur_use_buf, query->max_use_buf, query->max_use_buf ? (query->cur_use_buf * 100.0 / query->max_use_buf) : 0.0);
	info("pending request count: %zu / %zu (%.1f%%)", query->cur_use_que, query->max_use_que, query->max_use_que ? (query->cur_use_que * 100.0 / query->max_use_que) : 0.0);

	switch (cmd) {
		case xnbd_bgctl_cmd_unknown:
		case xnbd_bgctl_cmd_query:
			break;

		case xnbd_bgctl_cmd_switch:
			if (cached != nblocks) {
				if (force_enabled)
					info("switching to target mode despite incomplete cache, requested by --force");
				else
					err("refusing to switch to target mode with incomplete cache and no --force given");
			}

			{
				/*
				 * The bgctl command will perform an read operation to the unix socket,
				 * in order to make sure the termination of the proxy server. When the
				 * proxy server is terminated, the read operation will return. In some
				 * cases, the read operation will promptly return with an error code,
				 * if the proxy server was already terminated. In any case, the read
				 * operation can detect the termination of the proxy server.
				 */
				int monitor_fd = start_monitor_connection(unix_path);
				int ret = kill(query->master_pid, SIGUSR2);
				if (ret < 0)
					err("send SIGUSR2 to %d", query->master_pid);
				info("set xnbd (pid %d) to target mode", query->master_pid);
				wait_for_target_mode(monitor_fd);
			}
			break;

		case xnbd_bgctl_cmd_cache_all:
			// cache_all_blocks(unix_path, bm, nblocks);
			cache_all_blocks_async(unix_path, bm, query->disksize, progress_enabled, blocks_at_once);
			break;

		case xnbd_bgctl_cmd_cache_all2:
			cache_all_blocks_with_dedicated_connection(unix_path, bm, query);
			break;

		case xnbd_bgctl_cmd_reconnect:
			reconnect(unix_path, rhost, rport, exportname);
			break;

		default:
			err("bug: not reached");
	}


	g_free(query);
	bitmap_close_file(bm, bmlen);

	return 0;
}
