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


/* special entry to let threads exit */
struct proxy_priv priv_stop_forwarder = {
	.nreq = 0,
	.need_exit = 0,
	.iotype = NBD_CMD_UNDEFINED,
	.write_buff = NULL,
	.read_buff = NULL,
};

struct proxy_session {
	int nbd_fd;
	int wrk_fd;
	GAsyncQueue *tx_queue;
	struct xnbd_proxy *proxy;

	pthread_t tid_tx;
	pthread_t tid_rx;

	int pipe_write_fd; /* tx thread & rx thread */
	int pipe_read_fd;  /* main thread */
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


/* used in xnbd-tester */
void xnbd_proxy_control_cache_block(int ctl_fd, off_t disksize, unsigned long index, unsigned long nblocks)
{
	int ret;

	off_t iofrom = (off_t) index * CBLOCKSIZE;
	size_t iolen = nblocks * CBLOCKSIZE;
	iolen = confine_iolen_within_disk(disksize, iofrom, iolen);

	ret = nbd_client_send_request_header(ctl_fd, NBD_CMD_BGCOPY, iofrom, iolen, UINT64_MAX);
	if (ret < 0)
		err("send_read_request, %m");

	ret = nbd_client_recv_reply_header(ctl_fd, UINT64_MAX);
	if (ret < 0)
		err("recv header, %m");
}

#if 0
void wait_for_low_queue_load(struct proxy_session *ps)
{
	if (!ps->proxy->xnbd->proxy_max_queue_size)
		return;

	struct xnbd_proxy *proxy = ps->proxy;
	struct timespec sleep_time = { 0, 20*1000*1000 };

	for (;;) {
		const gint len_fwd_tx_queue = g_async_queue_length(proxy->fwd_tx_queue);
		const gint len_fwd_rx_queue = g_async_queue_length(proxy->fwd_rx_queue);
		const gint len_fwd_retry_queue = g_async_queue_length(proxy->fwd_retry_queue);
		const gint len_tx_queue = g_async_queue_length(ps->tx_queue);
		const guint len_total = MAX(len_fwd_tx_queue, 0)
				+ MAX(len_fwd_rx_queue, 0)
				+ MAX(len_fwd_retry_queue, 0)
				+ MAX(len_tx_queue, 0);

		dbg("QUEUE SIZES: fwd_tx = %d, fwd_rx = %d, fwd_retry = %d, tx = %d / total = %d",
				len_fwd_tx_queue, len_fwd_rx_queue, len_fwd_retry_queue, len_tx_queue,
				len_total);

		if (len_total < ps->proxy->xnbd->proxy_max_queue_size) {
			break;
		}
		nanosleep(&sleep_time, NULL);
	}
}
#endif


static void mem_usage_add(struct xnbd_proxy *proxy, struct proxy_priv *priv)
{
	/* both buffers should be never allocated at the same time */
	g_assert((priv->write_buff != NULL && priv->read_buff != NULL) == false);


	g_mutex_lock(&proxy->curr_use_mutex);

	if (proxy->xnbd->proxy_max_buf_size) {
		proxy->cur_use_buf += sizeof(struct proxy_priv);

		/* need to look up buffers, not iotype */
		if (priv->write_buff || priv->read_buff)
			proxy->cur_use_buf += priv->iolen;
	}

	if (proxy->xnbd->proxy_max_que_size)
		proxy->cur_use_que += 1;

	g_mutex_unlock(&proxy->curr_use_mutex);
}

static void mem_usage_wait(struct xnbd_proxy *proxy)
{
	for (;;) {
		bool mem_is_full = false;
		bool queue_is_full = false;

		g_mutex_lock(&proxy->curr_use_mutex);

		if (proxy->xnbd->proxy_max_buf_size) {
			if (G_UNLIKELY(proxy->cur_use_buf > proxy->xnbd->proxy_max_buf_size)) {
				mem_is_full = true;
			}
		}

		if (proxy->xnbd->proxy_max_que_size) {
			if (G_UNLIKELY(proxy->cur_use_que > proxy->xnbd->proxy_max_que_size)) {
				queue_is_full = true;
			}
		}

		g_mutex_unlock(&proxy->curr_use_mutex);

		if (G_LIKELY(!mem_is_full && !queue_is_full))
			break;

		if (mem_is_full)
			dbg("mem_usage reached limit %zu (bytes). Temporally suspend receiving new requests.",
					proxy->xnbd->proxy_max_buf_size);
		if (queue_is_full)
			dbg("queue_usage reached limit %zu. Temporally suspend receiving new requests.",
					proxy->xnbd->proxy_max_que_size);

		usleep(200*1000);
	}
}

static void mem_usage_del(struct xnbd_proxy *proxy, struct proxy_priv *priv)
{
	g_mutex_lock(&proxy->curr_use_mutex);

	if (proxy->xnbd->proxy_max_buf_size) {
		proxy->cur_use_buf -= sizeof(struct proxy_priv);

		/* need to look up buffers, not iotype */
		if (priv->write_buff || priv->read_buff)
			proxy->cur_use_buf -= priv->iolen;
	}

	if (proxy->xnbd->proxy_max_que_size)
		proxy->cur_use_que -= 1;

	g_mutex_unlock(&proxy->curr_use_mutex);
}


int recv_request(struct proxy_session *ps)
{
	struct xnbd_proxy *proxy = ps->proxy;
	int nbd_client_fd = ps->nbd_fd;
	/* The proxy server may intensively allocates/frees a huge number of
	 * proxy_priv objects. Use g_slice_ functions here because it is more
	 * efficient than malloc(). Even though a client (or xnbd-bgctl)
	 * queues a huge number of requests, the memory consumption of the
	 * proxy server will not largely exceed proxy_max_buf_size.
	 *
	 * Contrarily, using malloc() may cause the proxy server to consume
	 * huge memory beyond than proxy_max_buf_size.
	 *
	 * But, it should be noted that read_buff and write_buff are still
	 * allocated by malloc() because the buffer size of each request will
	 * be different. If proxy_max_buf_size is used, keep your eyes on
	 * memory consumption of the proxy server when a client (not
	 * xnbd-bgctl) intensively sends a large number of requests.
	 **/
	struct proxy_priv *priv = g_slice_new0(struct proxy_priv);


	uint32_t iotype = 0;
	off_t iofrom = 0;
	size_t iolen  = 0;
	int ret = 0;


	priv->nreq = 0;
	priv->clientfd = nbd_client_fd;
	priv->tx_queue = ps->tx_queue;
	priv->reply.magic = htonl(NBD_REPLY_MAGIC);
	priv->reply.error = 0;

	ret = wait_until_readable(nbd_client_fd, ps->wrk_fd);
	if (ret < 0)
		goto err_handle;

	ret = nbd_server_recv_request(nbd_client_fd, proxy->xnbd->disksize, &iotype, &iofrom, &iolen, &priv->reply);
	if (ret == -1) {
		/*
		 * A request with an invalid offset was received. The proxy
		 * server terminates this connection. This behavior is
		 * different from the original NBD server.
		 */
		goto err_handle;
	} else if (ret == -2) {
		warn("client bug: invalid header");
		goto err_handle;
	} else if (ret == -3) {
		goto err_handle;
	}

	dbg("++++ a new %s request received", nbd_get_iotype_string(iotype));

	if (proxy->xnbd->readonly) {
		if (iotype == NBD_CMD_WRITE) {
			warn("NBD_CMD_WRITE to a readonly server. disconnect.");
			goto err_handle;
		}
	}

	unsigned long block_index_sta = get_bindex_sta(CBLOCKSIZE, iofrom);
	unsigned long block_index_end = get_bindex_end(CBLOCKSIZE, iofrom + iolen);
	dbg("disk io iofrom %ju iolen %zu", iofrom, iolen);
	dbg("block_index_sta %lu stop %lu", block_index_sta, block_index_end);

	priv->iotype = iotype;
	priv->iofrom = iofrom;
	priv->iolen  = iolen;
	priv->block_index_start = block_index_sta;
	priv->block_index_end   = block_index_end;


	if (iotype == NBD_CMD_WRITE) {
		priv->write_buff = g_malloc(iolen);

		/*
		 * Receive write data to a temporary buffer.
		 *
		 * Cache disk I/O is allowed only in the completion thread.
		 * This ensures all disk I/O is serialized.
		 *
		 * If the proxy server wrote data to the cache disk here,
		 * the preceding requests might read/write the same range of
		 * the cache disk in the tx_thread after this writing.
		 **/
		ret = net_recv_all_or_error(priv->clientfd, priv->write_buff, priv->iolen);
		if (ret < 0) {
			warn("recv write data");
			goto err_handle;
		}


	} else if (iotype == NBD_CMD_READ) {
		priv->read_buff = g_malloc(iolen);

	} else if (iotype == NBD_CMD_BGCOPY) {
		/* do nothing here */
		;

	} else {
		warn("client bug: unknown iotype");
		goto err_handle;
	}


	// wait_for_low_queue_load(ps);
	mem_usage_wait(proxy);

	mem_usage_add(proxy, priv);
	g_async_queue_push(proxy->fwd_tx_queue, priv);


	return 0;


err_handle:
	info("start terminating session (nbd_fd %d wrk_fd %d)", ps->nbd_fd, ps->wrk_fd);
	priv->need_exit = 1;
	priv->iotype = NBD_CMD_UNDEFINED;

	mem_usage_add(proxy, priv);
	g_async_queue_push(proxy->fwd_tx_queue, priv);

	return -1;
}






void proxy_initialize_forwarder(struct xnbd_proxy *proxy, int remotefd)
{
	proxy->remotefd   = remotefd;
	proxy->tid_fwd_rx = pthread_create_or_abort(forwarder_rx_thread_main, proxy);
	proxy->tid_fwd_tx = pthread_create_or_abort(forwarder_tx_thread_main, proxy);
}

void proxy_shutdown_forwarder(struct xnbd_proxy *proxy)
{
	/*
	 * The purpose of the memory usage management is to avoid the situation
	 * where the server consumes extraordinary memory. It is not intended
	 * to accurately and strictly limit the memory use of the server.
	 *
	 * priv_stop_forwarder is a statically allocated object, and it is used
	 * only when the shutdown or reconnect of the proxy is invoked. I think
	 * it's okay that this object is out-of-scope of the memory usage
	 * management.
	 *
	 * Actually, the current code does not have mem_usage_del() for
	 * priv_stop_forwarder. See forwader_rx_thread_mainloop().
	 */
	g_async_queue_push(proxy->fwd_tx_queue, &priv_stop_forwarder);

	pthread_join(proxy->tid_fwd_tx, NULL);
	info("forwarder_tx exited");
	pthread_join(proxy->tid_fwd_rx, NULL);
	info("forwarder_rx exited");
}

/* called in a proxy process */
void proxy_initialize(struct xnbd_info *xnbd, struct xnbd_proxy *proxy)
{
	proxy->xnbd  = xnbd;

	/* keep reference count! */
	proxy->fwd_tx_queue = g_async_queue_new();
	proxy->fwd_rx_queue = g_async_queue_new();
	proxy->fwd_retry_queue = g_async_queue_new();


	/* set up a bitmap and a cache disk */
	proxy->cbitmap = bitmap_open_file(xnbd->proxy_bmpath, xnbd->nblocks, &proxy->cbitmaplen, 0, xnbd->proxy_clear_bitmap ? 1 : 0);

	int cachefd = open(xnbd->proxy_diskpath, O_RDWR | O_CREAT | O_NOATIME, S_IRUSR | S_IWUSR);
	if (cachefd < 0)
		err("open");

	off_t size = get_disksize(cachefd);
	if (size != xnbd->disksize) {
		warn("cache disk size (%ju) != target disk size (%ju)", size, xnbd->disksize);
		warn("now ftruncate() it");
		int ret = ftruncate(cachefd, xnbd->disksize);
		if (ret < 0)
			err("ftruncate");
	}

	proxy->cachefd = cachefd;
	g_mutex_init(&proxy->curr_use_mutex);
	proxy->cur_use_buf = 0;
	proxy->cur_use_que = 0;
}


void proxy_shutdown(struct xnbd_proxy *proxy)
{
	/* safe to access the values because no other threads are alive */
	g_mutex_clear(&proxy->curr_use_mutex);
	if (proxy->cur_use_buf != 0 || proxy->cur_use_que != 0)
		warn("cur_use_buf %zu cur_use_que %zu", proxy->cur_use_buf, proxy->cur_use_que);

	g_async_queue_unref(proxy->fwd_retry_queue);
	g_async_queue_unref(proxy->fwd_tx_queue);
	g_async_queue_unref(proxy->fwd_rx_queue);

	if (proxy->shared_buff)
		munmap_or_abort(proxy->shared_buff, XNBD_SHARED_BUFF_SIZE);

	close(proxy->cachefd);
	bitmap_close_file(proxy->cbitmap, proxy->cbitmaplen);
}




GList *conn_list = NULL;

struct proxy_session *get_session_from_read_fd(GList *list_head, int fd)
{
	for (GList *list = g_list_first(list_head); list != NULL; list = g_list_next(list)) {
		struct proxy_session *ps = (struct proxy_session *) list->data;
		if (ps->pipe_read_fd == fd)
			return ps;
	}

	return NULL;
}



void *rx_thread_main(void *arg)
{
	struct proxy_session *ps = (struct proxy_session *) arg;

	set_process_name("proxy_rx");

	block_all_signals();

	info("rx_thread %lu starts", pthread_self());


	for (;;) {
		int ret = recv_request(ps);
		if (ret < 0)
			break;
	}


	info("rx_thread %lu exits", pthread_self());

	return NULL;
}


void *tx_thread_main(void *arg)
{
	struct proxy_session *ps = (struct proxy_session *) arg;
	int need_exit = 0;
	int need_skip = 0;

	set_process_name("proxy_tx");

	block_all_signals();

	info("tx_thread %lu starts", pthread_self());

	for (;;) {
		struct proxy_priv *priv = g_async_queue_pop(ps->tx_queue);
		proxy_priv_dump(priv);

		if (priv->need_exit)
			need_exit = 1;
		else if (!need_skip) {
			/* setup iovec */
			struct iovec iov[2];
			unsigned int iov_size = 0;

			iov[iov_size].iov_base = &priv->reply;
			iov[iov_size].iov_len  = sizeof(struct nbd_reply);
			iov_size += 1;

			if (priv->iotype == NBD_CMD_READ) {
				iov[iov_size].iov_base = priv->read_buff;
				iov[iov_size].iov_len  = priv->iolen;
				iov_size += 1;
			}

			int ret = net_writev_all_or_error(priv->clientfd, iov, iov_size);
			if (ret < 0) {
				warn("clientfd %d is dead", priv->clientfd);
				/*
				 * tx_thread has detected that clientfd is unusable.
				 * tx_thread may dequeue requests from ps->tx_queue,
				 * but now skips sending their replies.
				 *
				 * The error of clientfd will be also detected by rx_thread.
				 * rx_thread will enqueue a special request with .need_exit=1;
				 * this request is a notification of graceful shutdown.
				 * tx_thread will finally receive this request.
				 */
				need_skip = 1;
			}
		}

		/* check the buffer pointer. Even if iotype is
		 * NBD_CMD_UNDEFINED, the buffer may be allocated. */
		if (priv->read_buff)
			g_free(priv->read_buff);

		if (priv->write_buff)
			g_free(priv->write_buff);

		mem_usage_del(ps->proxy, priv);
		g_slice_free(struct proxy_priv, priv);

		if (need_exit)
			break;
	}

	/* notify the main thread */
	net_send_all_or_abort(ps->pipe_write_fd, "", 1);

	info("tx_thread %lu exits", pthread_self());

	return NULL;
}


static gint unshift_func(gconstpointer a __attribute__((unused)),
		       gconstpointer b __attribute__((unused)),
			       gpointer user_data __attribute__((unused)))
{
	return -1;
}

static void g_async_queue_push_unshift(GAsyncQueue *queue, gpointer data)
{
	g_async_queue_push_sorted(queue, data, &unshift_func, NULL);
}

int main_loop(struct xnbd_proxy *proxy, int unix_listen_fd, int master_fd)
{
	int ret;
	struct pollfd eventfds[2 + g_list_length(conn_list)];
	nfds_t neventfds = 0;

	eventfds[neventfds].fd = unix_listen_fd;
	eventfds[neventfds].events = POLLRDNORM | POLLRDHUP;
	neventfds += 1;

	eventfds[neventfds].fd = master_fd;
	eventfds[neventfds].events = POLLRDNORM | POLLRDHUP;
	neventfds += 1;

	for (GList *list = g_list_first(conn_list); list != NULL; list = g_list_next(list)) {
		struct proxy_session *ps = (struct proxy_session *) list->data;
		eventfds[neventfds].fd = ps->pipe_read_fd;
		eventfds[neventfds].events = POLLRDNORM | POLLRDHUP;
		neventfds += 1;
	}


	int nready = poll(eventfds, neventfds, -1);
	if (nready == -1) {
		if (errno == EINTR) {
			info("polling signal cached");
			return -1;
		} else
			err("polling, %s, (%d)", strerror(errno), errno);
	}


	if (eventfds[0].revents & (POLLRDNORM | POLLRDHUP)) {
		/* register_fd arrived */
		struct sockaddr_un cliaddr;
		socklen_t cliaddr_len = sizeof(cliaddr);

		int wrk_fd = accept(eventfds[0].fd, &cliaddr, &cliaddr_len);
		if (wrk_fd < 0)
			err("accept %m");

		int close_wrk_fd = 1;
		enum xnbd_proxy_cmd_type cmd;
		ret = net_recv_all_or_error(wrk_fd, &cmd, sizeof(cmd));
		if (ret < 0)
			cmd = XNBD_PROXY_CMD_UNKNOWN;

		switch (cmd) {
			case XNBD_PROXY_CMD_QUERY_STATUS:
				{
					struct xnbd_proxy_query query;
					memset(&query, 0, sizeof(query));
					query.disksize = proxy->xnbd->disksize;
					g_strlcpy(query.diskpath, proxy->xnbd->proxy_diskpath, sizeof(query.diskpath));
					g_strlcpy(query.bmpath, proxy->xnbd->proxy_bmpath, sizeof(query.bmpath));
					g_strlcpy(query.rhost, proxy->xnbd->proxy_rhost, sizeof(query.rhost));
					g_strlcpy(query.rport, proxy->xnbd->proxy_rport, sizeof(query.rport));
					query.master_pid = getppid();

					query.max_use_buf = proxy->xnbd->proxy_max_buf_size;
					query.cur_use_buf = proxy->cur_use_buf;
					query.max_use_que = proxy->xnbd->proxy_max_que_size;
					query.cur_use_que = proxy->cur_use_que;

					info("send current status (wrk_fd %d)", wrk_fd);
					net_send_all_or_error(wrk_fd, &query, sizeof(query));
				}
				break;

			case XNBD_PROXY_CMD_REGISTER_FD:
				{
					int nbd_fd = unix_recv_fd(wrk_fd);
					info("create proxy_session (nbd_fd %d wrk_fd %d)", nbd_fd, wrk_fd);

					struct proxy_session *ps = g_malloc0(sizeof(struct proxy_session));
					ps->nbd_fd = nbd_fd;
					ps->wrk_fd = wrk_fd;
					ps->tx_queue = g_async_queue_new();
					ps->proxy = proxy;

					ps->tid_tx = pthread_create_or_abort(tx_thread_main, ps);
					ps->tid_rx = pthread_create_or_abort(rx_thread_main, ps);
					make_pipe(&ps->pipe_write_fd, &ps->pipe_read_fd);

					conn_list = g_list_append(conn_list, ps);
					close_wrk_fd = 0;
				}
				break;

			case XNBD_PROXY_CMD_REGISTER_FORWARDER_FD:
				{
					int fwd_fd = unix_recv_fd(wrk_fd);
					info("register forwarder fd (nbd_fd %d wrk_fd %d)", fwd_fd, wrk_fd);
					proxy_shutdown_forwarder(proxy);
					nbd_client_send_disc_request(proxy->remotefd);
					close(proxy->remotefd);

					for (;;) {
						struct proxy_priv *priv = g_async_queue_try_pop(proxy->fwd_retry_queue);
						if (!priv)
							break;

						priv->need_retry = 0;

						g_async_queue_push_unshift(proxy->fwd_tx_queue, priv);
					}

					proxy_initialize_forwarder(proxy, fwd_fd);
				}
				break;

			case XNBD_PROXY_CMD_REGISTER_SHARED_BUFFER_FD:
				{
					/* TODO use this */
					if (proxy->shared_buff)
						warn("shared_buff was already assigned; do nothing");
					else {
						int buf_fd = unix_recv_fd(wrk_fd);
						info("register shared buffer fd (buf_fd %d wrk_fd %d)", buf_fd, wrk_fd);

						proxy->shared_buff = mmap(NULL, XNBD_SHARED_BUFF_SIZE, PROT_READ, MAP_SHARED, buf_fd, 0);
						if (proxy->shared_buff == MAP_FAILED)
							err("mmap, %m");

						close(buf_fd);
					}
				}
				break;

			case XNBD_PROXY_CMD_DETECT_SWITCH:
				/*
				 * This command is used to detect the completion of the mode switch
				 * from the proxy to the target mode. After receiving this command,
				 * the proxy server does nothing special, but leaves the accepted
				 * socket open. This socket will be closed when the proxy server
				 * is terminated.
				 */
				close_wrk_fd = 0;
				break;

			case XNBD_PROXY_CMD_UNKNOWN:
			default:
				warn("unknown proxy cmd %d (wrk_fd %d)", cmd, wrk_fd);
		}

		if (close_wrk_fd)
			close(wrk_fd);
	}

	if (eventfds[1].revents & (POLLRDNORM | POLLRDHUP)) {
		info("mainloop exit is requested");

		/* The master server requested the exit of the proxy server.
		 * Before doing that, the master server terminated all the
		 * worker processes. Thus, the proxy server should not have any
		 * active connections at this moment. However, only the
		 * exceptional case is that the proxy server has the connection
		 * of xnbd-bgctl. For example, when "xnbd-bgctl --cache-all" is
		 * being executed, invoking "xnbd-bgctl --switch --force" or
		 * hitting CTRL-C for xnbd-server causes that exceptional case. */

		{
			unsigned int remaining_sessions = g_list_length(conn_list);
			if (remaining_sessions > 0) {
				/* If there is a non xnbd-bgctl session, it's a bug. */
				warn("terminate %u xnbd-bgctl session(s)", remaining_sessions);
			}
		}

		if (proxy->cur_use_buf != 0 || proxy->cur_use_que != 0)
			warn("terminate pending requests");

		/* if there are no sessions, run clean up and bye */

		return -1;
	}

	for (nfds_t i = 2; i < neventfds; i++) {
		if (eventfds[i].revents & (POLLRDNORM | POLLRDHUP)) {
			int pipe_read_fd  = eventfds[i].fd;
			struct proxy_session *ps = get_session_from_read_fd(conn_list, pipe_read_fd);
			g_assert(ps);

			info("cleanup proxy_session (nbd_fd %d wrk_fd %d)", ps->nbd_fd, ps->wrk_fd);

			/* rx_thread and tx_thread already exited */
			pthread_join(ps->tid_rx, NULL);
			pthread_join(ps->tid_tx, NULL);

			/* This assertion is called after we confirmed that
			 * there are no other threads using ps->tx_queue. When
			 * this proxy session was active, the tx thread (of the
			 * thread ID ps->tid_tx) was waiting for this queue.
			 * But, at this line, the code is in the cleanup phase.
			 * The session is not active and the thread already
			 * exited. If this assertion failed, it's a bug. */
			g_assert(g_async_queue_length(ps->tx_queue) == 0);
			g_async_queue_unref(ps->tx_queue);
			close(ps->pipe_read_fd);
			close(ps->pipe_write_fd);
			close(ps->nbd_fd);

			ret = write(ps->wrk_fd, "", 1);
			if (ret < 0)
				warn("notifying the worker process failed: %m");

			close(ps->wrk_fd);
			conn_list = g_list_remove(conn_list, ps);
			g_free(ps);

			info("cleanup proxy_session done");
		}
	}

	return 0;
}



/* before calling this function, all sessions must be terminated */
void xnbd_proxy_stop(struct xnbd_info *xnbd)
{
	g_assert(g_list_length(xnbd->sessions) == 0);

	/* request xnbd_proxy to exit */
	write_all(xnbd->proxy_sockpair_master_fd, "", 1);
	close(xnbd->proxy_sockpair_master_fd);

	int ret;
	ret = waitpid(xnbd->proxy_pid, NULL, 0);
	if (ret < 0)
		err("waitpid %d, %m", xnbd->proxy_pid);

	info("xnbd_proxy (pid %d) exited", xnbd->proxy_pid);
}


void xnbd_proxy_start(struct xnbd_info *xnbd)
{
	int ret;

	dbg("proxy server back start");

	info("proxymode mode %s %s (%s%s) cache %s cachebitmap %s",
			xnbd->proxy_rhost, xnbd->proxy_rport,
			xnbd->proxy_target_exportname ? "xnbd-wrapper:" : "xnbd-server",
			xnbd->proxy_target_exportname ? xnbd->proxy_target_exportname : "",
			xnbd->proxy_diskpath, xnbd->proxy_bmpath);

	int remotefd = net_connect(xnbd->proxy_rhost, xnbd->proxy_rport, SOCK_STREAM, IPPROTO_TCP);
	if (remotefd < 0)
		err("connecting %s:%s failed", xnbd->proxy_rhost, xnbd->proxy_rport);

	/* check the remote server and get a disksize */

	if (xnbd->proxy_target_exportname)
		ret = nbd_negotiate_with_server_new(remotefd, &(xnbd->disksize), NULL, strlen(xnbd->proxy_target_exportname), xnbd->proxy_target_exportname);
	else
		ret = nbd_negotiate_with_server2(remotefd, &(xnbd->disksize), NULL);

	if (ret < 0) {
		err("negotiation with %s:%s failed", xnbd->proxy_rhost, xnbd->proxy_rport);
	}

	xnbd->nblocks = get_disk_nblocks(xnbd->disksize);

	make_sockpair(&xnbd->proxy_sockpair_master_fd, &xnbd->proxy_sockpair_proxy_fd);

	pid_t pid = fork_or_abort();

	if (pid == 0) {
		/* -- child -- */
		set_process_name("proxy_main");

		close(xnbd->proxy_sockpair_master_fd);

		/* use xnbd->proxy_sockpair_master_fd to request exit */
		block_all_signals();

		struct xnbd_proxy *proxy = g_malloc0(sizeof(struct xnbd_proxy));
		proxy_initialize(xnbd, proxy);
		proxy_initialize_forwarder(proxy, remotefd);



		int unix_listen_fd = socket(AF_LOCAL, SOCK_STREAM, 0);
		if (unix_listen_fd < 0)
			err("socket %m");

		struct sockaddr_un srvaddr;
		srvaddr.sun_family = AF_LOCAL;
		g_strlcpy(srvaddr.sun_path, xnbd->proxy_unixpath, sizeof(srvaddr.sun_path));

		ret = bind(unix_listen_fd, &srvaddr, sizeof(srvaddr));
		if (ret < 0)
			err("binding to %s: %m", xnbd->proxy_unixpath);

		ret = listen(unix_listen_fd, 10);
		if (ret < 0)
			err("listening to %s: %m", xnbd->proxy_unixpath);

		info("xnbd_proxy (pid %d) remote %s:%s, cache %s (%s), ctl %s",
				getpid(), xnbd->proxy_rhost, xnbd->proxy_rport,
				xnbd->proxy_diskpath, xnbd->proxy_bmpath,
				xnbd->proxy_unixpath);

		/*
		 * Tell the master that xnbd_proxy gets ready. We need to send
		 * something to differentiate close() by abort.
		 **/
		net_send_all_or_abort(xnbd->proxy_sockpair_proxy_fd, "", 1);
		shutdown(xnbd->proxy_sockpair_proxy_fd, SHUT_WR);


		for (;;) {
			ret = main_loop(proxy, unix_listen_fd, xnbd->proxy_sockpair_proxy_fd);
			if (ret < 0) {
				break;
			}
		}


		/* send an exit message to forwarder threads and join them */

		proxy_shutdown_forwarder(proxy);
		proxy_shutdown(proxy);
		nbd_client_send_disc_request(proxy->remotefd);
		close(proxy->remotefd);
		g_free(proxy);
		close(unix_listen_fd);
		unlink(xnbd->proxy_unixpath);

		info("xnbd_proxy successfully exits");
		exit(EXIT_SUCCESS);
	}


	/* -- parent -- */

	xnbd->proxy_pid = pid;
	close(xnbd->proxy_sockpair_proxy_fd);
	close(remotefd);

	/* make sure the child is ready */
	char buf[1];
	net_recv_all_or_abort(xnbd->proxy_sockpair_master_fd, buf, 1);
	shutdown(xnbd->proxy_sockpair_master_fd, SHUT_RD);
	info("xnbd_proxy gets ready");
}


int xnbd_proxy_session_server(struct xnbd_session *ses)
{
	struct xnbd_info *xnbd = ses->xnbd;
	set_process_name("proxy_wrk");

	/* unix_fd is connected to ps->wrk_fd */
	int unix_fd = unix_connect(xnbd->proxy_unixpath);

	enum xnbd_proxy_cmd_type cmd = XNBD_PROXY_CMD_REGISTER_FD;
	net_send_all_or_abort(unix_fd, &cmd, sizeof(cmd));

	unix_send_fd(unix_fd, ses->clientfd);

	info("proxy worker: send fd %d via unix_fd %d",
			ses->clientfd, unix_fd);

	int ret;
	struct pollfd eventfds[2];
	nfds_t neventfds = 0;

	eventfds[neventfds].fd = unix_fd;
	eventfds[neventfds].events = POLLRDNORM | POLLRDHUP;
	neventfds += 1;

	eventfds[neventfds].fd = ses->pipe_worker_fd;
	eventfds[neventfds].events = POLLRDNORM | POLLRDHUP;
	neventfds += 1;

	block_all_signals();

	for (;;) {
		int nready = poll(eventfds, neventfds, -1);
		if (nready == -1) {
			if (errno == EINTR)
				err("proxy worker: catch an unexpected signal");
			else
				err("polling, %s, (%d)", strerror(errno), errno);
		}

		if (eventfds[0].revents & (POLLRDNORM | POLLRDHUP)) {
			char buf[1];
			ret = net_recv_all_or_error(eventfds[0].fd, buf, 1);
			if (ret < 0)
				warn("proxy worker: detect the incorrect termination of xnbd_proxy");
			else
				info("proxy worker: detect the session exited");

			break;

		} else if (eventfds[1].revents & (POLLRDNORM | POLLRDHUP)) {
			char buf[1];
			ret = net_recv_all_or_error(eventfds[1].fd, buf, 1);
			if (ret < 0) {
				err("proxy worker: the master server was incorrectly terminated?");
			} else
				info("proxy worker: be requested session termination");

			ret = net_send_all_or_error(unix_fd, "", 1);
			if (ret < 0)
				warn("proxy worker: sending session termination request failed");

			/* wait for the session exit in the next loop */
		} else
			err("not reached");
	}



	return 0;
}
