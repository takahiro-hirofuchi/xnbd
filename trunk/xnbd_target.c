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

#include "xnbd.h"



int target_mode_main_mmap(struct xnbd_session *ses)
{
	struct xnbd_info *xnbd = ses->xnbd;

	struct nbd_reply reply;
	int csock = ses->clientfd;
	uint32_t iotype = 0;
	off_t iofrom = 0;
	size_t iolen  = 0;
	int ret;

	bzero(&reply, sizeof(reply));
	reply.magic = htonl(NBD_REPLY_MAGIC);
	reply.error = 0;


	ret = poll_request_arrival(ses);
	if (ret < 0)
		return -1;

	ret = nbd_server_recv_request(csock, xnbd->disksize, &iotype, &iofrom, &iolen, &reply);
	if (ret == -1) {
		net_send_all_or_abort(csock, &reply, sizeof(reply));
		return 0;
	} else if (ret == -2)
		err("client bug: invalid header");
	else if (ret == -3)
		return ret;

	if (xnbd->readonly && iotype == NBD_CMD_WRITE) {
		/* do not read following write data */
		err("NBD_CMD_WRITE to a readonly disk. disconnect.");
	}

	dbg("direct mode");

	char *mmaped_buf = NULL;
	size_t mmaped_len = 0;
	off_t mmaped_offset = 0;
	char *iobuf = NULL;


	iobuf = mmap_iorange(xnbd, xnbd->diskfd, iofrom, iolen, &mmaped_buf, &mmaped_len, &mmaped_offset);
	dbg("mmaped_buf %p iobuf %p mmaped_len %zu iolen %zu", mmaped_buf, iobuf, mmaped_len, iolen);



	struct iovec iov[2];

	switch (iotype) {
		case NBD_CMD_WRITE:
			dbg("disk write iofrom %ju iolen %zu", iofrom, iolen);

			net_recv_all_or_abort(csock, iobuf, iolen);

			net_send_all_or_abort(csock, &reply, sizeof(reply));

			break;

		case NBD_CMD_READ:
			dbg("disk read iofrom %ju iolen %zu", iofrom, iolen);

			bzero(&iov, sizeof(iov));
			iov[0].iov_base = &reply;
			iov[0].iov_len  = sizeof(reply);
			iov[1].iov_base = iobuf;
			iov[1].iov_len  = iolen;

			net_writev_all_or_abort(csock, iov, 2);

			break;

		default:
			err("unknown command %u", iotype);
	}


	//ret = msync(mmaped_buf, mmaped_len, MS_SYNC);
	//if (ret < 0) 
	//	warn("msync failed");
	ret = munmap(mmaped_buf, mmaped_len);
	if (ret < 0) 
		warn("munmap failed");

#if 0
	if (iotype == NBD_CMD_READ)
		gstat_add(xnbd, iofrom);
#endif

	return 0;
}



int target_server(struct xnbd_session *ses)
{
	for (;;) {
		int ret = 0;

		ret = target_mode_main_mmap(ses);
		if (ret < 0)
			return ret;
	}

	return 0;
}
