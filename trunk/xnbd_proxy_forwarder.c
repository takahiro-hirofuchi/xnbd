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

void proxy_priv_dump(struct proxy_priv *priv)
{
	dbg("priv %p", priv);
	dbg(" nreq   %d", priv->nreq);
	for (int i = 0; i < priv->nreq; i++) {
		dbg("  bindex_iofrom %ju", priv->req[i].bindex_iofrom);
		dbg("  bindex_iolen  %u", priv->req[i].bindex_iolen);
	}

	dbg(" iofrom %ju", priv->iofrom);
	dbg(" iolen  %zu", priv->iolen);
	dbg(" block_index_start  %lu", priv->block_index_start);
	dbg(" block_index_end    %lu", priv->block_index_end);

	dbg(" reply.magic  %x", priv->reply.magic);
	dbg(" reply.error  %u", priv->reply.error);
	dbg(" reply.handle");
	//dump_buffer(priv->reply.handle, 8);
}



void add_read_block_to_tail(struct proxy_priv *priv, unsigned long i)
{
	int cur_nreq = priv->nreq;

	if (cur_nreq > 0) {
		struct remote_read_request *last_req = &priv->req[cur_nreq - 1];

		if (i == (last_req->bindex_iofrom + last_req->bindex_iolen)) {
			/* extend the iolen of the last request */
			last_req->bindex_iolen += 1;
			return;
		}
	}

	/* add a new request */
	priv->req[cur_nreq].bindex_iofrom = i;
	priv->req[cur_nreq].bindex_iolen  = 1;
	priv->nreq += 1;

	if (priv->nreq == MAXNBLOCK)
		err("bug, MAXNBLOCK is too small");
}




void prepare_read_priv(struct xnbd_proxy *proxy, struct proxy_priv *priv)
{
	struct xnbd_info *xnbd = proxy->ses->xnbd;
	unsigned long block_index_start = priv->block_index_start;
	unsigned long block_index_end   = priv->block_index_end;

	for (unsigned long i = block_index_start; i <= block_index_end; i++) {
		/* counter */
		cachestat_read_block();

		if (!bitmap_test(xnbd->cbitmap, i)) {
			/* this block will be cached later in the completion thread */
			bitmap_on(xnbd->cbitmap, i);

			/* counter */
			//monitor_cached_by_ondemand(i);
			cachestat_miss();
			cachestat_cache_odread();

			add_read_block_to_tail(priv, i);
		} else {

			/* counter */
			cachestat_hit();
		}

		if (priv->nreq == MAXNBLOCK)
			err("maximum priv->nreq %d", MAXNBLOCK);
	}


}


void prepare_write_priv(struct xnbd_proxy *proxy, struct proxy_priv *priv)
{
	struct xnbd_info *xnbd = proxy->ses->xnbd;
	unsigned long block_index_start = priv->block_index_start;
	unsigned long block_index_end   = priv->block_index_end;
	off_t iofrom = priv->iofrom;
	size_t iolen  = priv->iolen;


	/*
	 * First, send read requests for start/end blocks to a source node
	 * if they are partial blocks and not yet cached.
	 **/
	int get_start_block = 0;
	int get_end_block   = 0;

	{
		if (iofrom % CBLOCKSIZE)
			if (!bitmap_test(xnbd->cbitmap, block_index_start))
				get_start_block = 1;


		if ((iofrom + iolen) % CBLOCKSIZE) {
			/*
			 * Handle the end of the io range is not aligned.
			 * Case 1: The IO range covers more than one block.
			 * Case 2: One block, but the start of the io range is aligned.
			 */
			if ((block_index_end > block_index_start) ||
					((block_index_end == block_index_start) && !get_start_block))
				if (!bitmap_test(xnbd->cbitmap, block_index_end)) 
					get_end_block = 1;

			/* bitmap_on() is performed in the below forloop */
		}


		/*
		 * Mark all write data blocks as cached. The following I/O
		 * requests to this area never retrieve these blocks.
		 **/
		for (unsigned long i = block_index_start; i <= block_index_end; i++) {
			/* counter */
			cachestat_write_block();

			if (!bitmap_test(xnbd->cbitmap, i)) {
				bitmap_on(xnbd->cbitmap, i);

				/* counter */
				//monitor_cached_by_ondemand(i);
				cachestat_cache_odwrite();
			}
		}
	}

	if (get_start_block) {
		int cur_nreq = priv->nreq;
		priv->req[cur_nreq].bindex_iofrom = block_index_start;
		priv->req[cur_nreq].bindex_iolen  = 1;
		priv->nreq += 1;

		cachestat_miss();
	} else {
		cachestat_hit();
	}

	if (get_end_block) {
		int cur_nreq = priv->nreq;
		priv->req[cur_nreq].bindex_iofrom = block_index_end;
		priv->req[cur_nreq].bindex_iolen  = 1;
		priv->nreq += 1;

		cachestat_miss();
	} else {
		cachestat_hit();
	}


	g_assert(priv->nreq < MAXNBLOCK);


	/*
	 * For a WRITE request, we recieved all write data from the client.
	 * But, a reply must be sent later in the completion thread.
	 * send(clientfd) may be blocked while holding send_lock.
	 *
	 * The completion threads holds send_lock, and unfortunately sometimes
	 * becomes blocked due to a TCP flow control: A client is still
	 * submitting the following requests, and not recieving replies from a
	 * server.
	 * The main thread is blocked for send_lock, and cannot recieve the
	 * following requests anymore.
	 *
	 * Also, the reordering of request results should be avoided?
	 *
	 * If the completion thread is sending READ reply data, and at the same
	 * time the main thread is sending a reply, a deadlock occurs.
	 *
	 * Therefore, sending reply should be done in the completion thread.
	 *
	 * UPDATE: the main thread does not perform send() to the client
	 * anymmore; send(clientfd) is only performed at the completion thread.
	 * So, we remove send_lock for clientfd.
	 **/
}


