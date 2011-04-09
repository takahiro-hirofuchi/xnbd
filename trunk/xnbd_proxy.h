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



struct remote_read_request {
	/* block index */
	off_t bindex_iofrom;
	size_t bindex_iolen;
};

#define MAXNBLOCK 10

struct proxy_priv {
	/* notify a request error. skip io */
	int notify_error;

	uint32_t iotype;

	/* number of remote read requests */
	int nreq;
	struct remote_read_request req[MAXNBLOCK];

	off_t iofrom;
	size_t iolen;

	unsigned long block_index_start;
	unsigned long block_index_end;

	struct nbd_reply reply;

	char *write_buff;
};



struct xnbd_proxy {
	pthread_t tid_cmp, tid_srq;

	/* queues for main and bg threads */
	GAsyncQueue *high_queue;

	/* queue for the read request waiting a reply */
	GAsyncQueue *req_queue;

	struct xnbd_session *ses;
};

