/* 
 * xNBD - an enhanced Network Block Device program
 *
 * Copyright (C) 2008-2012 National Institute of Advanced Industrial Science
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

void reconnect(char *unix_path, char *rhost, char *rport)
{
	int fd = unix_connect(unix_path);

	int fwd_fd = net_connect(rhost, rport, SOCK_STREAM, IPPROTO_TCP);
	nbd_negotiate_with_server(fwd_fd);

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

void cache_block_range(char *unix_path, unsigned long *bm, unsigned long disk_nblocks, int remote_fd, char *shared_buff)
{
	int ctl_fd, unix_fd;
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
		int ret = nbd_client_send_read_request(remote_fd, iofrom, iolen);
		if (ret < 0)
			err("send_read_request, %m");

		ret = nbd_client_recv_read_reply(remote_fd, shared_buff, iolen);
		if (ret < 0)
			err("recv_read_reply, %m");

		xnbd_proxy_control_cache_block(ctl_fd, index, nblocks);
	}


	end_register_fd(unix_fd, ctl_fd);
}

void cache_all_blocks_with_dedicated_connection(char *unix_path, unsigned long *bm, struct xnbd_proxy_query *query)
{
	int remote_fd = net_connect(query->rhost, query->rport, SOCK_STREAM, IPPROTO_TCP);
	if (remote_fd < 0)
		err("connect, %m");

	off_t remote_disksize = nbd_negotiate_with_server(remote_fd);
	if (remote_disksize != query->disksize)
		err("disksize mismatch");


	char *shared_buff = setup_shared_buffer(unix_path);

	unsigned long nblocks = get_disk_nblocks(query->disksize);
	cache_block_range(unix_path, bm, nblocks, remote_fd, shared_buff);

	close_shared_buffer(shared_buff);

	nbd_client_send_disc_request(remote_fd);
	close(remote_fd);
}


struct cache_rx_ctl {
	int ctl_fd;
	GAsyncQueue *q;
};

char cache_rx_req_eof;
char cache_rx_req_data;

void *cache_all_blocks_receiver_main(void *arg)
{
	struct cache_rx_ctl *cache_rx = (struct cache_rx_ctl *) arg;

	set_process_name("cache_rx");
	block_all_signals();
	info("create cache_rx thread %lu", pthread_self());

	for (;;) {
		char *data = g_async_queue_pop(cache_rx->q);
		if (data == &cache_rx_req_eof)
			break;

		int ret = nbd_client_recv_header(cache_rx->ctl_fd);
		if (ret < 0)
			err("recv header, %m");
	}

	info("done cache_rx thread %lu", pthread_self());

	return NULL;
}

void cache_all_blocks_async(char *unix_path, unsigned long *bm, unsigned long nblocks)
{
	int unix_fd, ctl_fd;
	start_register_fd(unix_path, &unix_fd, &ctl_fd);

	struct cache_rx_ctl cache_rx;
	cache_rx.ctl_fd = ctl_fd;
	cache_rx.q      = g_async_queue_new();
	pthread_t cache_rx_tid = pthread_create_or_abort(cache_all_blocks_receiver_main, &cache_rx);

	for (unsigned long index = 0; index < nblocks; index++) {
		if (!bitmap_test(bm, index)) {
			off_t iofrom = (off_t) index * CBLOCKSIZE;
			// size_t iolen = nblocks * CBLOCKSIZE;
			size_t iolen = CBLOCKSIZE;

			int ret = nbd_client_send_request_header(ctl_fd, NBD_CMD_BGCOPY, iofrom, iolen, (UINT64_MAX));
			if (ret < 0)
				err("send_read_request, %m");

			g_async_queue_push(cache_rx.q, &cache_rx_req_data);
		}
	}

	g_async_queue_push(cache_rx.q, &cache_rx_req_eof);
	pthread_join(cache_rx_tid, NULL);
	g_async_queue_unref(cache_rx.q);

	end_register_fd(unix_fd, ctl_fd);
}




void cache_all_blocks(char *unix_path, unsigned long *bm, unsigned long nblocks)
{
	int unix_fd, ctl_fd;
	start_register_fd(unix_path, &unix_fd, &ctl_fd);

	for (unsigned long index = 0; index < nblocks; index++) {
		if (!bitmap_test(bm, index)) {
			xnbd_proxy_control_cache_block(ctl_fd, index, 1);
		}
	}

	end_register_fd(unix_fd, ctl_fd);
}

unsigned long get_cached(unsigned long *bm, unsigned long nblocks)
{
	unsigned long cached = 0;
	for (unsigned long index = 0; index < nblocks; index++) {
		if (bitmap_test(bm, index))
			cached += 1;
	}

	return cached;
}

static struct option longopts[] = {
	/* commands */
	{"query",      no_argument, NULL, 'q'},
	{"shutdown",   no_argument, NULL, 's'},
	{"cache-all",  no_argument, NULL, 'c'},
	{"cache-all2", no_argument, NULL, 'C'},
	{"reconnect",  no_argument, NULL, 'r'},
	{"help",       no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0},
};

static const char *help_string = "\
Usage:\n\
  xnbd-bgctl --query       CONTROL_UNIX_SOCKET\n\
  xnbd-bgctl --shutdown    CONTROL_UNIX_SOCKET\n\
  xnbd-bgctl --cache-all   CONTROL_UNIX_SOCKET\n\
  xnbd-bgctl --cache-all2  CONTROL_UNIX_SOCKET\n\
  xnbd-bgctl --reconnect   CONTROL_UNIX_SOCKET REMOTE_HOST REMOTE_PORT\n\
\n\
Commands:\n\
  --query       query current status of the proxy mode\n\
  --cache-all   cache all blocks\n\
  --cache-all2  cache all blocks with the background connection\n\
  --shutdown    shutdown the proxy mode and start the target mode\n\
  --reconnect   reconnect the forwarding session\n\
";


void show_help_and_exit(const char *msg)
{
	if (msg)
		info("%s\n", msg);

	fprintf(stderr, "%s\n", help_string);
	exit(msg ? EXIT_FAILURE : EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	g_thread_init(NULL);

	enum xnbd_bgctl_cmd_type {
		xnbd_bgctl_cmd_unknown,
		xnbd_bgctl_cmd_query,
		xnbd_bgctl_cmd_cache_all,
		xnbd_bgctl_cmd_cache_all2,
		xnbd_bgctl_cmd_shutdown,
		xnbd_bgctl_cmd_reconnect,
	} cmd = xnbd_bgctl_cmd_unknown;

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

				cmd = xnbd_bgctl_cmd_shutdown;
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

			case '?':
				show_help_and_exit("unknown option");
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
		case xnbd_bgctl_cmd_shutdown:
		case xnbd_bgctl_cmd_query:
		case xnbd_bgctl_cmd_unknown:
			if (argc - optind == 1)
				unix_path = argv[optind];
			else
				show_help_and_exit("specify a control socket file");
	}




	size_t bmlen;

	struct xnbd_proxy_query *query = create_proxy_query(unix_path);
	unsigned long nblocks = get_disk_nblocks(query->disksize);
	unsigned long *bm = bitmap_open_file(query->bmpath, nblocks, &bmlen, 1, 0);
	unsigned long cached = get_cached(bm, nblocks);

	info("%s (%s): disksize %ju", query->diskpath, query->bmpath, query->disksize);
	info("forwarded to %s:%s", query->rhost, query->rport);
	info("cached blocks %lu / %lu (%.1f%%)", cached, nblocks, nblocks ? (cached * 100.0 / nblocks) : 0.0);

	switch (cmd) {
		case xnbd_bgctl_cmd_unknown:
		case xnbd_bgctl_cmd_query:
			break;

		case xnbd_bgctl_cmd_shutdown:
			{
				int ret = kill(query->master_pid, SIGHUP);
				if (ret < 0)
					err("send SIGHUP to %d", query->master_pid);
			}
			info("set xnbd (pid %d) to target mode", query->master_pid);
			break;

		case xnbd_bgctl_cmd_cache_all:
			// cache_all_blocks(unix_path, bm, nblocks);
			cache_all_blocks_async(unix_path, bm, nblocks);
			break;

		case xnbd_bgctl_cmd_cache_all2:
			cache_all_blocks_with_dedicated_connection(unix_path, bm, query);
			break;

		case xnbd_bgctl_cmd_reconnect:
			reconnect(unix_path, rhost, rport);
			break;

		default:
			err("bug: not reached");
	}


	g_free(query);
	bitmap_close_file(bm, bmlen);

	return 0;
}
