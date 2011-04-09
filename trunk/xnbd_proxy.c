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

struct xnbd_cread {
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

	char *pending_write_buff;
};


/* special entry to let threads exit */
struct xnbd_cread cread_eof = { .notify_error = 0, .nreq = 0 };



struct xnbd_proxy {
	pthread_t tid_cmp, tid_srq;

	/* cached bitmap rwlock */
	pthread_rwlock_t cbitmaplock;

	/* queues for main and bg threads */
	GAsyncQueue *high_queue;

	/* queue for the read request waiting a reply */
	GAsyncQueue *req_queue;

	struct xnbd_session *ses;
};


void block_all_signals(void)
{
	sigset_t sig;
	int ret = sigfillset(&sig);
	if (ret < 0) 
		err("sigfillset");

	ret = pthread_sigmask(SIG_SETMASK, &sig, NULL);
	if (ret < 0)
		err("sigmask");
}

void xnbd_cread_dump(struct xnbd_cread *cread)
{
	dbg("cread %p", cread);
	dbg(" nreq   %d", cread->nreq);
	for (int i = 0; i < cread->nreq; i++) {
		dbg("  bindex_iofrom %ju", cread->req[i].bindex_iofrom);
		dbg("  bindex_iolen  %lu", cread->req[i].bindex_iolen);
	}

	dbg(" iofrom %ju", cread->iofrom);
	dbg(" iolen  %zu", cread->iolen);
	dbg(" block_index_start  %lu", cread->block_index_start);
	dbg(" block_index_end    %lu", cread->block_index_end);

	dbg(" reply.magic  %x", cread->reply.magic);
	dbg(" reply.error  %u", cread->reply.error);
	dbg(" reply.handle");
	//dump_buffer(cread->reply.handle, 8);
}

void cbitmap_read_lock(struct xnbd_proxy *proxy)
{
	int ret;

	dbg("get read lock ... ");
	ret = pthread_rwlock_rdlock(&proxy->cbitmaplock);
	if (ret < 0)
		err("deadlock?");
	dbg("got read lock");
}

void cbitmap_unlock(struct xnbd_proxy *proxy)
{
	int ret;

	dbg("unlock ... ");
	ret = pthread_rwlock_unlock(&proxy->cbitmaplock);
	if (ret < 0)
		err("unlock");
	dbg("unlocked");
}

void cbitmap_write_lock(struct xnbd_proxy *proxy)
{
	int ret;

	dbg("get write lock ... ");
	ret = pthread_rwlock_wrlock(&proxy->cbitmaplock);
	if (ret < 0)
		err("deadlock?");
	dbg("got write lock");
}



		
void add_read_block_to_tail(struct xnbd_cread *cread, unsigned long i)
{
	int cur_nreq = cread->nreq;

	if (cur_nreq > 0) {
		struct remote_read_request *last_req = &cread->req[cur_nreq - 1];

		if (i == (last_req->bindex_iofrom + last_req->bindex_iolen)) {
			/* extend the iolen of the last request */
			last_req->bindex_iolen += 1;
			return;
		}
	}

	/* add a new request */
	cread->req[cur_nreq].bindex_iofrom = i;
	cread->req[cur_nreq].bindex_iolen  = 1;
	cread->nreq += 1;

	if (cread->nreq == MAXNBLOCK)
		err("bug, MAXNBLOCK is too small");
}




int proxy_mode_main_read(struct xnbd_proxy *proxy, struct xnbd_cread *cread)
{
	struct xnbd_info *xnbd = proxy->ses->xnbd;
	unsigned long block_index_start = cread->block_index_start;
	unsigned long block_index_end   = cread->block_index_end;

	cbitmap_write_lock(proxy);
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

			add_read_block_to_tail(cread, i);
		} else {

			/* counter */
			cachestat_hit();
		}

		if (cread->nreq == MAXNBLOCK)
			err("maximum cread->nreq %d", MAXNBLOCK);
	}
	cbitmap_unlock(proxy);



	g_async_queue_push(proxy->high_queue, (gpointer) cread);

	return 0;
}


int proxy_mode_main_write(struct xnbd_proxy *proxy, struct xnbd_cread *cread)
{
	struct xnbd_info *xnbd = proxy->ses->xnbd;
	unsigned long block_index_start = cread->block_index_start;
	unsigned long block_index_end   = cread->block_index_end;
	off_t iofrom = cread->iofrom;
	size_t iolen  = cread->iolen;


	/*
	 * First, send read requests for start/end blocks to a source node
	 * if they are partial blocks and not yet cached.
	 **/
	int get_start_block = 0;
	int get_end_block   = 0;

	cbitmap_write_lock(proxy);
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
	cbitmap_unlock(proxy);

	if (get_start_block) {
		int cur_nreq = cread->nreq;
		cread->req[cur_nreq].bindex_iofrom = block_index_start;
		cread->req[cur_nreq].bindex_iolen  = 1;
		cread->nreq += 1;

		cachestat_miss();
	} else {
		cachestat_hit();
	}

	if (get_end_block) {
		int cur_nreq = cread->nreq;
		cread->req[cur_nreq].bindex_iofrom = block_index_end;
		cread->req[cur_nreq].bindex_iolen  = 1;
		cread->nreq += 1;

		cachestat_miss();
	} else {
		cachestat_hit();
	}

	if (cread->nreq >= MAXNBLOCK)
		err("more MAXNBLOCK is required");


	/*
	 * Next, recieve write data from a client node.
	 * Recieve all blocks to a temporariy buffer because the completion
	 * thread may touch the same range of the cache buffer.
	 * Touching the cache buffer should be allowed only in the completon thread.
	 **/
	cread->pending_write_buff = g_malloc(iolen);


	int ret = net_recv_all_or_error(proxy->ses->clientfd, cread->pending_write_buff, iolen);
	if (ret < 0)
		err("recv write data");

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

	g_async_queue_push(proxy->high_queue, (gpointer) cread);

	return 0;
}



int proxy_mode_main(struct xnbd_proxy *proxy)
{
	struct xnbd_session *ses = proxy->ses;

	uint32_t iotype = 0;
	off_t iofrom = 0;
	size_t iolen  = 0;
	int ret = 0;



	ret = poll_request_arrival(ses);
	if (ret < 0) 
		return -1;



	struct xnbd_cread *cread = g_malloc0(sizeof(struct xnbd_cread));

	cread->reply.magic = htonl(NBD_REPLY_MAGIC);
	cread->reply.error = 0;

	ret = nbd_server_recv_request(ses->clientfd, ses->xnbd->disksize, &iotype, &iofrom, &iolen, &cread->reply);
	if (ret == -1) {
		cread->notify_error = 1;
		g_async_queue_push(proxy->high_queue, (gpointer) cread);
		return 0;
	} else if (ret == -2) {
		g_free(cread);
		err("client bug: invalid header");
	} else if (ret == -3) {
		g_free(cread);
		return ret;
	}


	dbg("++++recv new request");


	unsigned long block_index_start;
	unsigned long block_index_end;

	get_io_range_index(iofrom, iolen, &block_index_start, &block_index_end);
	dbg("disk io iofrom %ju iolen %zu", iofrom, iolen);
	dbg("block_index_start %lu stop %lu", block_index_start, block_index_end);

	cread->iotype = iotype;
	cread->iofrom = iofrom;
	cread->iolen  = iolen;
	cread->nreq = 0;
	cread->block_index_start = block_index_start;
	cread->block_index_end   = block_index_end;




	if (iotype == NBD_CMD_READ)
		ret = proxy_mode_main_read(proxy, cread);
	else if (iotype == NBD_CMD_WRITE)
		ret = proxy_mode_main_write(proxy, cread);
	else 
		err("client bug: uknown iotype");


	return ret;
}





int complete_thread_main(struct xnbd_proxy *proxy)
{
	struct xnbd_session *ses = proxy->ses;
	struct xnbd_info *xnbd = ses->xnbd;

	struct xnbd_cread *cread;
	int ret;

	dbg("wait new queue element");


	cread = (struct xnbd_cread *) g_async_queue_pop(proxy->req_queue);
	dbg("--- process new queue element %p", cread);

	xnbd_cread_dump(cread);


	if (cread->notify_error) {
		net_send_all_or_abort(proxy->ses->clientfd, &cread->reply, sizeof(struct nbd_reply));

		goto skip_cacheio;
	}

	if (cread == &cread_eof)
		return -1;


	/* large file support on 32bit architecutre */
	char *mmaped_buf = NULL;
	size_t mmaped_len = 0;
	off_t mmaped_offset = 0;
	char *iobuf = NULL;

	iobuf = mmap_iorange(xnbd, xnbd->cachefd, cread->iofrom, cread->iolen, &mmaped_buf, &mmaped_len, &mmaped_offset);
	dbg("#mmaped_buf %p iobuf %p mmaped_len %zu iolen %zu", mmaped_buf, iobuf, mmaped_len, cread->iolen);
	dbg("#mapped %p -> %p", mmaped_buf, mmaped_buf + mmaped_len);


	for (int i = 0; i < cread->nreq; i++) {
		dbg("cread req %d", i);
		off_t block_iofrom = cread->req[i].bindex_iofrom * CBLOCKSIZE;
		size_t block_iolen  = cread->req[i].bindex_iolen  * CBLOCKSIZE;
		char *iobuf_partial = NULL;

		iobuf_partial = mmaped_buf + (block_iofrom - mmaped_offset);

		dbg("i %u block_iofrom %ju iobuf_partial %p", i, block_iofrom, iobuf_partial);

		/* recv from server */
		ret = nbd_client_recv_read_reply(ses->remotefd, iobuf_partial, block_iolen);
		if (ret < 0) {
			warn("recv_read_reply error");
			cread->reply.error = htonl(EPIPE);
			net_send_all_or_abort(ses->clientfd, &cread->reply, sizeof(struct nbd_reply));

			/*
			 * TODO
			 * If the remote server is disconnected, the proxy
			 * server falls back to a pseudo target mode.
			 *
			 * N.B. make sure that a client still need this nbd disk. 
			 **/
			exit(EXIT_FAILURE);
		}

		/*
		 * Do not mark cbitmap here. Do it before. Otherwise, when the
		 * following request covers an over-wrapped I/O region, the
		 * main thread may retrieve remote blocks and overwrite them to
		 * an updated region.
		 **/
	}

	if (cread->iotype == NBD_CMD_READ) {
		struct iovec iov[2];
		bzero(&iov, sizeof(iov));

		iov[0].iov_base = &cread->reply;
		iov[0].iov_len  = sizeof(struct nbd_reply);
		iov[1].iov_base = iobuf;
		iov[1].iov_len  = cread->iolen;

		net_writev_all_or_abort(ses->clientfd, iov, 2);

	} else if (cread->iotype == NBD_CMD_WRITE) {
		/*
		 * This memcpy() must come before sending reply, so that xnbd-tester
		 * avoids memcmp() mismatch.
		 **/
		memcpy(iobuf, cread->pending_write_buff, cread->iolen);
		g_free(cread->pending_write_buff);

		net_send_all_or_abort(ses->clientfd, &cread->reply, sizeof(struct nbd_reply));


		/* Do not mark cbitmap here. */

	} else if (cread->iotype == NBD_CMD_BGCOPY) {
		/* NBD_CMD_BGCOPY does not do nothing here */
		;
	}


	ret = munmap(mmaped_buf, mmaped_len);
	if (ret < 0) 
		warn("munmap failed");



	dbg("send reply to client done");

skip_cacheio:
	g_free(cread);

	return 0;
}

void *redirect_thread(void *arg)
{
	struct xnbd_proxy *proxy = (struct xnbd_proxy *) arg;
	struct xnbd_session *ses = proxy->ses;
	struct xnbd_info *xnbd = ses->xnbd;


	block_all_signals();

	info("redirect_th %lu", pthread_self());


	/* 
	 * The current code redirects I/O requests while holding sreq_lock.
	 * Until all the queued requests are processed here, the recvreq thread
	 * and the bgctrl thread cannot enqueue the next request. 
	 *
	 * This behavior is probably appropriate for reducing I/O latencies;
	 * queued requests are redirected (if needed) as soon as possible,
	 * without being intrrupted by the threads. Is this true?
	 */

	for (;;) {
		for (;;) {
			struct xnbd_cread *cread;

			cread = (struct xnbd_cread *) g_async_queue_pop(proxy->high_queue);


			dbg("%lu --- process new queue element", pthread_self());


			/* send read request as soon as possible */
			for (int i = 0; i < cread->nreq; i++) {
				size_t length = cread->req[i].bindex_iolen * CBLOCKSIZE;

				int ret = nbd_client_send_read_request(ses->remotefd, cread->req[i].bindex_iofrom * CBLOCKSIZE, length);
				if (ret < 0) {
					/*
					 * TODO
					 * Should the proxy server fall back to a target mode?
					 */
					err("proxy: sending read request failed");
				}
			}

			g_async_queue_push(proxy->req_queue, (gpointer) cread);


			if (cread == &cread_eof)
				goto out_of_loop;
		}
	}

out_of_loop:


	info("bye redirect_th");
	return NULL;
}

void *complete_thread(void *arg)
{
	struct xnbd_proxy *proxy = (struct xnbd_proxy *) arg;


	block_all_signals();

	info("new complete thread %lu", pthread_self());

	for (;;) {
		int ret = complete_thread_main(proxy);
		if (ret < 0)
			break;
	}


	info("bye complete thread");

	return NULL;
}

static void signal_handler_xnbd(int i)
{
	info("signal catched xnbd, code %d", i);
}

static void set_signal_xnbd_service(void)
{
	struct sigaction act;

	bzero(&act, sizeof(act));
	act.sa_handler = signal_handler_xnbd;
	sigemptyset(&act.sa_mask);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
}



/* called in a proxy process */
void xnbd_proxy_initialize(struct xnbd_session *ses, struct xnbd_proxy *proxy)
{
	int ret;


	g_thread_init(NULL);


	proxy->ses  = ses;

	/* keep reference count! */
	proxy->high_queue = g_async_queue_new();
	proxy->req_queue = g_async_queue_new();




	ret = pthread_rwlock_init(&proxy->cbitmaplock, NULL);
	if (ret < 0)
		err("rwlock_init");

	proxy->tid_cmp = pthread_create_or_abort(complete_thread, proxy);
	proxy->tid_srq = pthread_create_or_abort(redirect_thread, proxy);

}

void xnbd_proxy_shutdown(struct xnbd_proxy *proxy)
{



	g_async_queue_push(proxy->high_queue, &cread_eof);

	pthread_join(proxy->tid_srq, NULL);
	info("redirect_th cancelled");
	pthread_join(proxy->tid_cmp, NULL);
	info("complete_th cancelled");




	g_async_queue_unref(proxy->high_queue);
	g_async_queue_unref(proxy->req_queue);

	pthread_rwlock_destroy(&proxy->cbitmaplock);

}



int proxy_server(struct xnbd_session *ses)
{
	int ret = 0;

	dbg("proxy server start");


	/* only the main thread accepts signal */
	set_signal_xnbd_service();

	struct xnbd_proxy *proxy = g_malloc0(sizeof(struct xnbd_proxy));

	xnbd_proxy_initialize(ses, proxy);

	for (;;) {
		ret = proxy_mode_main(proxy);
		if (ret < 0) { 
			/*
			 * NBD_CMD_DISC (disconnect) was recieved
			 * or proxy's shutdown was requested by other components.
			 **/
			break;
		}
	}


	xnbd_proxy_shutdown(proxy);
	g_free(proxy);

	//send_disc_request(xnbd->remotefd);

	return ret;
}
