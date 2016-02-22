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


static inline double get_duration(struct timeval *tv_sta, struct timeval *tv_end)
{
	double val = tv_end->tv_sec - tv_sta->tv_sec;
	val += 1.0L * (tv_end->tv_usec - tv_sta->tv_usec) /1000 /1000;

	return val;
}

void gettimeofday_or_abort(struct timeval *tv)
{
	int ret = gettimeofday(tv, NULL);
	if (ret < 0)
		err("gettimeofday");
}


static void fill_buffer(char *buff, size_t len)
{
	for (size_t i = 0; i < len; i++)
		buff[i] = (unsigned char) i;
}


const size_t cnst_iosize = 4096 * 4;

static void speed_test(int remotefd)
{
	off_t disksize;
	int ret = nbd_negotiate_v1_client_side(remotefd, &disksize, NULL);
	if (ret < 0)
		err("negotiation failed");
	info("remote disk size %ju", disksize);

	char *buff = g_malloc(cnst_iosize);
	fill_buffer(buff, cnst_iosize);

	for (;;) {
		struct timeval tv_sta;
		struct timeval tv_end;

		gettimeofday_or_abort(&tv_sta);

		for (off_t iofrom = 0; iofrom < disksize; iofrom += cnst_iosize) {
			/* should not go over the last offset */
			size_t iosize = cnst_iosize;
			if (iofrom + (off_t) cnst_iosize > disksize)
				iosize = disksize - iofrom;

			// info("iofrom %ju iosize %zu", iofrom, iosize);

			int ret = nbd_client_send_request_header(remotefd, NBD_CMD_WRITE, iofrom, iosize, UINT64_MAX);
			if (ret < 0)
				err("send a request header");

			net_send_all_or_abort(remotefd, buff, iosize);

			ret =  nbd_client_recv_reply_header(remotefd, UINT64_MAX);
			if (ret < 0)
				err("recv");
		}

		gettimeofday_or_abort(&tv_end);

		double duration = get_duration(&tv_sta, &tv_end);
		info("%lf MB/s", disksize / duration / 1024 / 1024);
	}

	g_free(buff);
}




int main(int argc, char **argv)
{
	if (argc != 3)
		err("command line");

	char *rhost = argv[1];
	char *rport = argv[2];

	int remotefd = net_connect(rhost, rport, SOCK_STREAM, IPPROTO_TCP);
	if (remotefd < 0)
		err("connect to server");

	speed_test(remotefd);

	nbd_client_send_disc_request(remotefd);
	close(remotefd);

	return 0;
}
