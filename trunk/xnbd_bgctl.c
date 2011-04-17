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

	int fwd_fd = net_tcp_connect(rhost, rport);
	nbd_negotiate_with_server(fwd_fd);

	enum xnbd_proxy_cmd_type cmd = XNBD_PROXY_CMD_REGISTER_FORWARDER_FD;
	net_send_all_or_abort(fd, &cmd, sizeof(cmd));
	unix_send_fd(fd, fwd_fd);

	close(fd);
}

void cache_all_blocks(char *unix_path, unsigned long *bm, unsigned long nblocks)
{
	int fd = unix_connect(unix_path);

	int ctl_fd, proxy_fd;
	make_sockpair(&ctl_fd, &proxy_fd);

	enum xnbd_proxy_cmd_type cmd = XNBD_PROXY_CMD_REGISTER_FD;
	net_send_all_or_abort(fd, &cmd, sizeof(cmd));
	unix_send_fd(fd, proxy_fd);
	close(proxy_fd);

	for (unsigned long index = 0; index < nblocks; index++) {
		if (!bitmap_test(bm, index)) {
			off_t iofrom = index * CBLOCKSIZE;
			size_t iolen = CBLOCKSIZE;
			int ret;

			ret = nbd_client_send_read_request(ctl_fd, iofrom, iolen);
			if (ret < 0)
				err("send_read_request, %m");

			char *buf = g_malloc(iolen);
			ret = nbd_client_recv_read_reply(ctl_fd, buf, iolen);
			if (ret < 0)
				err("recv_read_reply");

			g_free(buf);
		}
	}

	close(ctl_fd);
	/* make sure this session is cleaned up in xnbd_proxy */
	char buf[1];
	net_recv_all_or_abort(fd, buf, 1);

	close(fd);
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
	{"query", no_argument, NULL, 'q'},
	{"cache-all-blocks", no_argument, NULL, 'c'},
	{"restart-as-target", no_argument, NULL, 'r'},
	{"reconnect", no_argument, NULL, 'R'},
	{NULL, 0, NULL, 0},
};

static const char *help_string = "\
Usage: \n\
  xnbd-bgctl {Options} control_unix_socket \n\
\n\
Options: \n\
  --query              query current status of xnbd_proxy \n\
  --cache-all-blocks   cache all blocks \n\
  --restart-as-target  restart all sessions as target mode \n\
";


void show_help_and_exit(const char *msg)
{
	if (msg)
		info("%s\n", msg);

	fprintf(stderr, "%s\n", help_string);
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	enum xnbd_bgctl_cmd_type {
		xnbd_bgctl_cmd_unknown,
		xnbd_bgctl_cmd_query,
		xnbd_bgctl_cmd_cache_all_blocks,
		xnbd_bgctl_cmd_restart_as_target,
		xnbd_bgctl_cmd_reconnect,
	} cmd = xnbd_bgctl_cmd_unknown;

	for (;;) {
		int c;
		int index = 0;

		c = getopt_long(argc, argv, "qcrR", longopts, &index);
		if (c == -1) /* all options were parsed */
			break;

		switch (c) {
			case 'q':
				if (cmd != xnbd_bgctl_cmd_unknown)
					show_help_and_exit("specify one mode");
			
				cmd = xnbd_bgctl_cmd_query;
				break;

			case 'c':
				if (cmd != xnbd_bgctl_cmd_unknown)
					show_help_and_exit("specify one mode");

				cmd = xnbd_bgctl_cmd_cache_all_blocks;
				break;

			case 'r':
				if (cmd != xnbd_bgctl_cmd_unknown)
					show_help_and_exit("specify one mode");

				cmd = xnbd_bgctl_cmd_restart_as_target;
				break;

			case 'R':
				if (cmd != xnbd_bgctl_cmd_unknown)
					show_help_and_exit("specify one mode");

				cmd = xnbd_bgctl_cmd_reconnect;
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

		case xnbd_bgctl_cmd_cache_all_blocks:
		case xnbd_bgctl_cmd_restart_as_target:
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
	info("forwaded to %s:%s", query->rhost, query->rport);
	info("cached blocks %lu / %lu", cached, nblocks);

	switch (cmd) {
		case xnbd_bgctl_cmd_unknown:
		case xnbd_bgctl_cmd_query:
			break;

		case xnbd_bgctl_cmd_cache_all_blocks:
			cache_all_blocks(unix_path, bm, nblocks);
			break;

		case xnbd_bgctl_cmd_restart_as_target:
			{
				int ret = kill(query->master_pid, SIGHUP);
				if (ret < 0)
					err("send SIGHUP to %d", query->master_pid);
			}
			info("set xnbd (pid %d) to target mode", query->master_pid);
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
