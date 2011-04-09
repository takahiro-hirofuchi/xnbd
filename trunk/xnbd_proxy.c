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

/* special entry to let threads exit */
struct proxy_priv priv_eof = { .notify_error = 0, .nreq = 0 };


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



	struct proxy_priv *priv = g_malloc0(sizeof(struct proxy_priv));

	priv->reply.magic = htonl(NBD_REPLY_MAGIC);
	priv->reply.error = 0;

	ret = nbd_server_recv_request(ses->clientfd, ses->xnbd->disksize, &iotype, &iofrom, &iolen, &priv->reply);
	if (ret == -1) {
		priv->notify_error = 1;
		g_async_queue_push(proxy->high_queue, (gpointer) priv);
		return 0;
	} else if (ret == -2) {
		g_free(priv);
		err("client bug: invalid header");
	} else if (ret == -3) {
		g_free(priv);
		return ret;
	}


	dbg("++++recv new request");


	unsigned long block_index_start;
	unsigned long block_index_end;

	get_io_range_index(iofrom, iolen, &block_index_start, &block_index_end);
	dbg("disk io iofrom %ju iolen %zu", iofrom, iolen);
	dbg("block_index_start %lu stop %lu", block_index_start, block_index_end);

	priv->iotype = iotype;
	priv->iofrom = iofrom;
	priv->iolen  = iolen;
	priv->nreq = 0;
	priv->block_index_start = block_index_start;
	priv->block_index_end   = block_index_end;





	if (iotype == NBD_CMD_READ)
		proxy_mode_main_read(proxy, priv);
	else if (iotype == NBD_CMD_WRITE) {
		/*
		 * Next, recieve write data from a client node.
		 * Recieve all blocks to a temporariy buffer because the completion
		 * thread may touch the same range of the cache buffer.
		 * Touching the cache buffer should be allowed only in the completon thread.
		 **/
		priv->write_buff = g_malloc(iolen);


		int ret = net_recv_all_or_error(proxy->ses->clientfd, priv->write_buff, iolen);
		if (ret < 0)
			err("recv write data");

		proxy_mode_main_write(proxy, priv);
	} else 
		err("client bug: uknown iotype");

	g_async_queue_push(proxy->high_queue, (gpointer) priv);


	return ret;
}





int complete_thread_main(struct xnbd_proxy *proxy)
{
	struct xnbd_session *ses = proxy->ses;
	struct xnbd_info *xnbd = ses->xnbd;

	struct proxy_priv *priv;
	int ret;

	dbg("wait new queue element");


	priv = (struct proxy_priv *) g_async_queue_pop(proxy->req_queue);
	dbg("--- process new queue element %p", priv);

	proxy_priv_dump(priv);


	if (priv->notify_error) {
		net_send_all_or_abort(proxy->ses->clientfd, &priv->reply, sizeof(struct nbd_reply));

		goto skip_cacheio;
	}

	if (priv == &priv_eof)
		return -1;


	/* large file support on 32bit architecutre */
	char *mmaped_buf = NULL;
	size_t mmaped_len = 0;
	off_t mmaped_offset = 0;
	char *iobuf = NULL;

	iobuf = mmap_iorange(xnbd, xnbd->cachefd, priv->iofrom, priv->iolen, &mmaped_buf, &mmaped_len, &mmaped_offset);
	dbg("#mmaped_buf %p iobuf %p mmaped_len %zu iolen %zu", mmaped_buf, iobuf, mmaped_len, priv->iolen);
	dbg("#mapped %p -> %p", mmaped_buf, mmaped_buf + mmaped_len);


	for (int i = 0; i < priv->nreq; i++) {
		dbg("priv req %d", i);
		off_t block_iofrom = priv->req[i].bindex_iofrom * CBLOCKSIZE;
		size_t block_iolen  = priv->req[i].bindex_iolen  * CBLOCKSIZE;
		char *iobuf_partial = NULL;

		iobuf_partial = mmaped_buf + (block_iofrom - mmaped_offset);

		dbg("i %u block_iofrom %ju iobuf_partial %p", i, block_iofrom, iobuf_partial);

		/* recv from server */
		ret = nbd_client_recv_read_reply(ses->remotefd, iobuf_partial, block_iolen);
		if (ret < 0) {
			warn("recv_read_reply error");
			priv->reply.error = htonl(EPIPE);
			net_send_all_or_abort(ses->clientfd, &priv->reply, sizeof(struct nbd_reply));

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

	if (priv->iotype == NBD_CMD_READ) {
		struct iovec iov[2];
		bzero(&iov, sizeof(iov));

		iov[0].iov_base = &priv->reply;
		iov[0].iov_len  = sizeof(struct nbd_reply);
		iov[1].iov_base = iobuf;
		iov[1].iov_len  = priv->iolen;

		net_writev_all_or_abort(ses->clientfd, iov, 2);

	} else if (priv->iotype == NBD_CMD_WRITE) {
		/*
		 * This memcpy() must come before sending reply, so that xnbd-tester
		 * avoids memcmp() mismatch.
		 **/
		memcpy(iobuf, priv->write_buff, priv->iolen);
		g_free(priv->write_buff);

		net_send_all_or_abort(ses->clientfd, &priv->reply, sizeof(struct nbd_reply));


		/* Do not mark cbitmap here. */

	} else if (priv->iotype == NBD_CMD_BGCOPY) {
		/* NBD_CMD_BGCOPY does not do nothing here */
		;
	}


	ret = munmap(mmaped_buf, mmaped_len);
	if (ret < 0) 
		warn("munmap failed");



	dbg("send reply to client done");

skip_cacheio:
	g_free(priv);

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
			struct proxy_priv *priv;

			priv = (struct proxy_priv *) g_async_queue_pop(proxy->high_queue);


			dbg("%lu --- process new queue element", pthread_self());


			/* send read request as soon as possible */
			for (int i = 0; i < priv->nreq; i++) {
				size_t length = priv->req[i].bindex_iolen * CBLOCKSIZE;

				int ret = nbd_client_send_read_request(ses->remotefd, priv->req[i].bindex_iofrom * CBLOCKSIZE, length);
				if (ret < 0) {
					/*
					 * TODO
					 * Should the proxy server fall back to a target mode?
					 */
					err("proxy: sending read request failed");
				}
			}

			g_async_queue_push(proxy->req_queue, (gpointer) priv);


			if (priv == &priv_eof)
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





	proxy->tid_cmp = pthread_create_or_abort(complete_thread, proxy);
	proxy->tid_srq = pthread_create_or_abort(redirect_thread, proxy);

}

void xnbd_proxy_shutdown(struct xnbd_proxy *proxy)
{



	g_async_queue_push(proxy->high_queue, &priv_eof);

	pthread_join(proxy->tid_srq, NULL);
	info("redirect_th cancelled");
	pthread_join(proxy->tid_cmp, NULL);
	info("complete_th cancelled");




	g_async_queue_unref(proxy->high_queue);
	g_async_queue_unref(proxy->req_queue);


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
