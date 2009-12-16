/* 
 * Copyright (C) 2008-2009 National Institute of Advanced Industrial Science and Technology
 */

#include "xnbd.h"

int bgctl_mode = 0;
char *bgctlpath;

static void fill_random(char *buff, uint32_t len)
{
	for (uint32_t i = 0; i < len; i++) {
		uint32_t rvalue = random();
		buff[i] = (char) rvalue;
	}
}

static int send_request_header(int remotefd, uint32_t iotype, uint64_t iofrom, uint32_t len, uint64_t handle)
{
	struct nbd_request request;

	dbg("send_request_header iofrom %ju len %u", iofrom, len);

	bzero(&request, sizeof(request));

	request.magic = htonl(NBD_REQUEST_MAGIC);
	request.type = htonl(iotype);
	request.from = htonll(iofrom);
	request.len = htonl(len);

	/* handle is 'char handle[8]' */
	memcpy(request.handle, &handle, 8);

	net_send_all_or_abort(remotefd, &request, sizeof(request));

	return 0;
}


struct crequest {
	uint32_t iotype;
	uint64_t iofrom;
	uint32_t iolen;

	char *write_buff;

	uint32_t index;
};


struct crequest eofmarker = { .write_buff = NULL };


uint64_t bgctl_disksize = 0;
pthread_mutex_t bgthread_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  bgthread_init_done = PTHREAD_COND_INITIALIZER;
pthread_t bgthread_tid;
int bgctlfd = 0;

int bgcopycount = 0;

void *bgctl_thread_main(void *data)
{
	uint64_t disksize = bgctl_disksize;
	uint32_t nblocks = disksize / CBLOCKSIZE;
	int ret;


	bgcopycount = 0;

	for (;;) {
		info("try open %s", bgctlpath);
		bgctlfd = open(bgctlpath, O_WRONLY);
		if (bgctlfd < 0) {
			warn("open bgctl %s, %m", bgctlpath);
			sleep(1);
			continue;
		}
		break;
	}

	info("open %s done", bgctlpath);

	pthread_mutex_lock(&bgthread_lock);
	pthread_cond_signal(&bgthread_init_done);
	pthread_mutex_unlock(&bgthread_lock);


	for (;;) {
		uint32_t bindex =  ((uint64_t) nblocks) * random() / RAND_MAX;

		ret = write(bgctlfd, &bindex, sizeof(bindex));
		if (ret != sizeof(bindex))
			err("write bgctl");

		info("%d bgctl bindex %u (iofrom %ju)\n", bgcopycount, bindex, (uint64_t) bindex * CBLOCKSIZE);

		bgcopycount += 1;

		//poll(NULL, 0, ((int) (2.0 * random() / (RAND_MAX + 1.0))));
		poll(NULL, 0, ((int) (20LL * random() / (RAND_MAX + 1.0))));


		if (bgcopycount > 1000)
			break;
	}

	close(bgctlfd);

	g_message("bgthread bye");

	return NULL;
}

void bgctl_thread_create(uint64_t disksize)
{
	int ret;

	bgctl_disksize = disksize;

	/* mutex_lock must come before pthread_create. Before cond_wait() is
	 * called, cond_signal() cannot notify anyone. Without mutex here, if
	 * bgthread finishes rapidly before cond_wait() is called, cond_wait()
	 * never wakes up. */
	pthread_mutex_lock(&bgthread_lock);

	ret = pthread_create(&bgthread_tid, NULL, bgctl_thread_main, NULL);
	if (ret < 0)
		err("create thread");


	pthread_cond_wait(&bgthread_init_done, &bgthread_lock);
	pthread_mutex_unlock(&bgthread_lock);
	g_message("bgthread creation done");
}

void bgctl_wait_shutdown(void)
{
	g_message("wait bgctl");
	pthread_join(bgthread_tid, NULL);
	g_message("wait done");
}


GAsyncQueue *reply_pendings;
GAsyncQueue *check_pendings;


struct parameters {
	uint32_t nreq;
	enum TestMode {
		TESTRDONLY = 1,
		TESTWRONLY,
		TESTRDWR,
	} testmode;
	uint64_t disksize;
	int remotefd;

	char *tgtbuf;


};

void *sender_thread_main(void *data)
{
	struct parameters *params = (struct parameters *) data;


	for (uint32_t index = 0; index < params->nreq; index++) {
		struct crequest *req = g_malloc0(sizeof(struct crequest));
		dbg("address %p", req);

		if (params->testmode == TESTRDWR)
			if (random() % 2)
				req->iotype = NBD_CMD_READ;
			else
				req->iotype = NBD_CMD_WRITE;
		else if (params->testmode == TESTRDONLY)
			req->iotype = NBD_CMD_READ;
		else if (params->testmode == TESTWRONLY)
			req->iotype = NBD_CMD_WRITE;
		else
			err("unkown testmode");


		req->iofrom = params->disksize * random() / RAND_MAX;
		uint32_t tmp_iolen = 1 + ((uint32_t) (10000.0 * (random() / (RAND_MAX + 1.0))));

		/*
		 * MIN() is a macro. So, calling random() in its
		 * argument may result in twice calling of it.
		 **/
		req->iolen  = MIN(tmp_iolen, (params->disksize - req->iofrom));

		g_message("index %d req %p iotype %s iofrom %ju iolen %u", index, req,
				(req->iotype == NBD_CMD_READ) ? "read" : "write",
				req->iofrom, req->iolen);

		if (req->iofrom + req->iolen > params->disksize) {
			g_message("disksize %ju", params->disksize);
			g_error("random, %ju", params->disksize);
		}

		send_request_header(params->remotefd, req->iotype, req->iofrom, req->iolen, (uint64_t) index);

		if (req->iotype == NBD_CMD_WRITE) {
			req->write_buff = g_malloc(req->iolen);
			fill_random(req->write_buff, req->iolen);
			net_send_all_or_abort(params->remotefd, req->write_buff, req->iolen);
		}

		req->index = index;
		g_async_queue_push(reply_pendings, req);

		poll(NULL, 0, ((int) (10LL * random() / (RAND_MAX + 1.0))));
	}



	g_async_queue_push(reply_pendings, &eofmarker);

	g_message("%d requests were sent", params->nreq);

	return NULL;
}

void *receiver_thread_main(void *data)
{
	struct parameters *params = (struct parameters *) data;

	for (;;) {
		struct crequest *req = g_async_queue_pop(reply_pendings);
		if (req == &eofmarker)
			break;

		struct nbd_reply reply;
		bzero(&reply, sizeof(reply));

		net_recv_all_or_abort(params->remotefd, &reply, sizeof(reply));

		if (ntohl(reply.magic) != NBD_REPLY_MAGIC)
			err("unknown reply magic, %x %x", reply.magic, ntohl(reply.magic));

		uint32_t error = ntohl(reply.error);
		if (error)
			err("reply state error %d", error);

		uint64_t reply_index = 0;

		memcpy(&reply_index, reply.handle, 8);
		dbg("index %llu", reply_index);

		if (req->index != reply_index)
			err("wrong reply ordering");

		dbg("address %p", req);
		dbg("index %d iofrom %llu iolen %u", req->index, req->iofrom, req->iolen);

		if (req->iotype == NBD_CMD_WRITE) {
			g_message("index %d req %p write done", req->index, req);

			memcpy(params->tgtbuf + req->iofrom, req->write_buff, req->iolen);

			//g_free(req->write_buff);

		} else if (req->iotype == NBD_CMD_READ) {
			net_recv_all_or_abort(params->remotefd, params->tgtbuf + req->iofrom, req->iolen);

			g_message("index %d req %p read done", req->index, req);

		} else
			err("bug");


		g_async_queue_push(check_pendings, req);
	}

	g_async_queue_push(check_pendings, &eofmarker);

	g_message("io finished");

	return NULL;
}

int test_direct_mode(char *srcdisk, char *tgtdisk, int remotefd, int testmode)
{
	int srcdiskfd;
	uint64_t disksize = 0;
	int result = 0;

	time_t now = time(NULL);
	srandom(now);

	reply_pendings = g_async_queue_new();
	check_pendings = g_async_queue_new();

	nbd_negotiate_with_server(remotefd, &disksize);
	g_message("remote disk size %llu", disksize);

	sleep(3);

	srcdiskfd = open(srcdisk, O_RDONLY);
	if (srcdiskfd < 0)
		err("src disk open");

	uint64_t srcdisksize = get_disksize(srcdiskfd);
	if (disksize != srcdisksize)
		err("disk size not match, %llu", srcdisksize);

	char *srcbuf = mmap(NULL, srcdisksize, PROT_READ, MAP_SHARED, srcdiskfd, 0);
	if (srcbuf == MAP_FAILED)
		err("srcdisk %s mapping failed, %s", srcdisk, strerror(errno));


	int tgtdiskfd = open(tgtdisk, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (tgtdiskfd < 0)
		err("tgt disk open %s", strerror(errno));

	{
		off_t ret = lseek(tgtdiskfd, disksize-1, SEEK_SET);
		if (ret < 0)
			err("lseek");
		
		ret = write(tgtdiskfd, "\0", 1);
		if (ret < 0)
			err("write");
	}


	char *tgtbuf = mmap(NULL, disksize, PROT_READ | PROT_WRITE, MAP_SHARED, tgtdiskfd, 0);
	if (tgtbuf == MAP_FAILED)
		err("tgtdisk %s mapping failed, %s", tgtdisk, strerror(errno));


	uint64_t testcount = 0;


	struct parameters params = {
		.nreq = 1000,
		.remotefd = remotefd,
		.disksize = disksize,
		.testmode = testmode,
		.tgtbuf = tgtbuf,
	};


	for (int loop_per_session = 0; loop_per_session < 100; loop_per_session++) {
		g_message("io start");
		if (bgctl_mode)
			bgctl_thread_create(disksize);


		int aaa = ((int) (1000LL * random() / (RAND_MAX + 1.0)));
		poll(NULL, 0, aaa);

		pthread_t tid_sender = pthread_create_or_abort(sender_thread_main, &params);
		pthread_t tid_receiver = pthread_create_or_abort(receiver_thread_main, &params);


		pthread_join(tid_sender, NULL);
		pthread_join(tid_receiver, NULL);

		if (bgctl_mode)
			bgctl_wait_shutdown();


		g_message("sender and receiver finished");
		/* wait here. make sure the last write is committed to the disk */
		//sleep(1);
		g_message("checking start ...");

		for (;;) {
			//struct crequest *req = pendings[i];
			struct crequest *req = g_async_queue_pop(check_pendings);
			if (req == &eofmarker)
				break;

			char *srciobuf = srcbuf + req->iofrom;
			char *tgtiobuf = tgtbuf + req->iofrom;

			int ret = memcmp(srciobuf, tgtiobuf, req->iolen);

			if (ret) {
				g_warning("mismatch index %d iotype %s iofrom %llu iolen %u",
						req->index, (req->iotype == NBD_CMD_READ) ? "read" : "write",
						req->iofrom, req->iolen);

				uint32_t block_index_start;
				uint32_t block_index_end;
				get_io_range_index(req->iofrom, req->iolen, &block_index_start, &block_index_end);

				g_message("iofrom %llu (%llu KB), block_index_start %u offset_in_start_block %llu",
						req->iofrom, req->iofrom / 1024,
						block_index_start, req->iofrom % CBLOCKSIZE);

				g_message("ioend %llu (%llu KB), block_index_end %u offset_in_end_block %llu",
						req->iofrom + req->iolen, (req->iofrom + req->iolen) / 1024,
						block_index_end, (req->iofrom + req->iolen) % CBLOCKSIZE);

				g_message("srcbuf ...");
				dump_buffer_all(srciobuf, req->iolen);
				g_message("tgtbuf ...");
				dump_buffer_all(tgtiobuf, req->iolen);
				if (req->iotype == NBD_CMD_WRITE) {
					g_message("req->write_buff");
					dump_buffer_all(req->write_buff, req->iolen);
				}


				int found = 0;
				for (uint32_t j = 0; j < req->iolen; j++) {
					char x0 = *(srciobuf + j);
					char x1 = *(tgtiobuf + j);
					if (x0 != x1) {
						g_message("mismatch at %d byte, %c %c", j, x0, x1);
						found = 1;
						break;
					}
				}
				if (!found)
					g_message("not mismatched !?");

				result = -1;
				goto err_out;
			}

			if (req->iotype == NBD_CMD_WRITE)
				g_free(req->write_buff);
			g_free(req);
		}


		g_message("checking done");

		g_message("## test %llu done, bgcopycount %d", testcount, bgcopycount);
		sleep(1);
		//sleep(1);
		testcount +=1;
	}

err_out:
	close(srcdiskfd);
	close(tgtdiskfd);
	munmap(srcbuf, disksize);
	munmap(tgtbuf, disksize);

	return result;
}


#if 0
int tester2(int remotefd, uint64_t iofrom, uint32_t iolen, char *filename, int isread)
{
	char *buf;
	int localfd;
	int ret;

	g_message("%s iofrom %llu size %u", (isread ? "read" : "write"), iofrom, iolen);

	buf = g_malloc(iolen);

	localfd = open(filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (localfd < 0)
		err("open localfd");

	if (isread) {
		diskio_remote(remotefd, iofrom, buf, iolen, 1);

		ret = write(localfd, buf, iolen);
		if (ret < 0)
			err("write error");

		g_message("read  %d bytes from remote", iolen);
		g_message("write %d bytes to   %s", ret, filename);
	} else {
		ret = read(localfd, buf, iolen);
		if (ret < 0)
			err("read error");

		diskio_remote(remotefd, iofrom, buf, ret, 0);
		g_message("read  %d bytes from %s", ret, filename);
		g_message("write %d bytes to   remote", ret);
	}

	close(localfd);

	return 0;
}
#endif

static void set_sigactions()
{
	struct sigaction act;

	bzero(&act, sizeof(act));
	act.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &act, NULL);
}

int main(int argc, char **argv) {
	int optind = 1;

	if (argc - optind != 7) {
		info("make xnbd-server-test xnbd-tester");
		info("For target mode");
		info("  ./xnbd-server-test --target disk1G.img --lport 8992");
		info("  ./xnbd-tester localhost 8992 disk1G.img /tmp/tmp.img 1 0 dummyarg");
		info(" ");
		info("For proxy mode");
		info("  ./xnbd-server-test --target disk1G.img --lport 8992");
		info("  ./xnbd-server-test --proxy localhost 8992 /tmp/disk.cache /tmp/disk.cache.bitmap --lport 8521 --bgctlprefix /tmp/xnbd-bg.ctl");
		info("  ./xnbd-tester localhost 8521 /tmp/disk.cache /tmp/tmp.img 1 0 /tmp/xnbd-bg.ctl");
		info(" ");
		err("See source code for detail.");
	}

	char *remotehost = argv[optind];
	char *remoteport = argv[optind + 1];
	char *srcpath = argv[optind + 2];     /* disk file (target), cache file (proxy) */
	char *dstpath = argv[optind + 3];     /* temporary space */
	int mode = atoi(argv[optind + 4]);    /* test readonly(1), writeonly(2), readwrite(3) */
	bgctl_mode = atoi(argv[optind + 5]);  /* test bgctl(1) or not(0) */
	bgctlpath = argv[optind + 6];

	if (bgctl_mode)
		g_message("bgctl is on");
	else
		g_message("bgctl is off");


	set_sigactions();
	g_thread_init(NULL);

	/* @srcdisk: disk file for a direct mode, cache file for a redirect mode */
	/* @dstdisk: temporary space */
	g_message("srcdisk %s dstdisk %s", srcpath, dstpath);


	unlink(bgctlpath);

	for (;;) {
		int remotefd = net_tcp_connect(remotehost, remoteport);

		int ret = test_direct_mode(srcpath, dstpath, remotefd, mode);
		if (ret < 0)
			return 1;

		send_disc_request(remotefd);
		close(remotefd);
	}

	return 0;
}
