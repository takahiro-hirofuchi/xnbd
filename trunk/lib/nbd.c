/* 
 * Copyright (C) 2008-2009 National Institute of Advanced Industrial Science and Technology
 *
 * Author: Takahiro Hirofuchi
 */
#include "nbd.h"

void nbd_request_dump(struct nbd_request *request)
{
	info("nbd_request %p", request);
	info(" request.magic  %x %x", request->magic, ntohl(request->magic));
	info(" request.type  %u %u", request->type, ntohl(request->type));
	info(" request.from  %ju %ju", request->from, ntohll(request->from));
	info(" request.len  %u %u", request->len, ntohl(request->len));
	info(" request.handle");
	dump_buffer(request->handle, 8);
}

void nbd_reply_dump(struct nbd_reply *reply)
{
	info("nbd_reply %p", reply);
	info(" reply.magic  %x %x", reply->magic, ntohl(reply->magic));
	info(" reply.error  %u %u", reply->error, ntohl(reply->magic));
	info(" reply.handle");
	dump_buffer(reply->handle, 8);
}


int nbd_client_send_request_header(int remotefd, uint32_t iotype, off_t iofrom, size_t len, uint64_t handle)
{
	g_assert(len <= UINT32_MAX);
	g_assert(iofrom + len <= OFF_MAX);
	g_assert(iofrom >= 0);

	dbg("send_request_header iofrom %ju len %zu", iofrom, len);


	struct nbd_request request;
	bzero(&request, sizeof(request));

	request.magic = htonl(NBD_REQUEST_MAGIC);
	request.type = htonl(iotype);
	request.from = htonll(iofrom);
	request.len = htonl(len);

	/* handle is 'char handle[8]' */
	memcpy(request.handle, &handle, 8);

	ssize_t ret = net_send_all(remotefd, &request, sizeof(request));
	if (ret < (ssize_t) sizeof(request)) {
		warn("send header");
		return -1;
	}

	return 0;
}


// static const char myhandle[8] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static const uint64_t myhandle = UINT64_MAX;

int nbd_client_send_read_request(int remotefd, off_t iofrom, size_t len)
{
	dbg("sending request of iotype %s iofrom %ju len %zu",
			"read", iofrom, len);

	return nbd_client_send_request_header(remotefd, NBD_CMD_READ, iofrom, len, myhandle);
}


#if 0
int send_read_request(int remotefd, off_t iofrom, size_t len)
{
	struct nbd_request request;
	int ret;

	dbg("sending request of iotype %s iofrom %ju len %zu",
			"read", iofrom, len);

	g_assert(len <= UINT32_MAX);
	g_assert(iofrom + len <= OFF_MAX);

	bzero(&request, sizeof(request));

	request.magic = htonl(NBD_REQUEST_MAGIC);
	request.type = htonl(NBD_CMD_READ);
	request.from = htonll(iofrom);
	request.len = htonl(len);

	/* handle is 'char handle[8]' */
	memcpy(request.handle, myhandle, 8);

	ret = net_send_all(remotefd, &request, sizeof(request));
	if (ret < (ssize_t) sizeof(request)) {
		warn("send header");
		return -1;
	}

	return 0;
}
#endif


int nbd_client_recv_read_reply(int remotefd, char *buf, size_t len)
{
	struct nbd_reply reply;
	int ret;

	dbg("now reciving read reply");

	g_assert(buf);
	g_assert(len <= UINT32_MAX);

	bzero(&reply, sizeof(reply));

	ret = net_recv_all_or_error(remotefd, &reply, sizeof(reply));
	if (ret < 0) {
		warn("proxy error: redirect tcp down");
		return -EPIPE;
	}

	//nbd_reply_dump(&reply);

	if (ntohl(reply.magic) != NBD_REPLY_MAGIC) {
		warn("proxy error: unknown reply magic, %x %x", reply.magic, ntohl(reply.magic));
		return -EPIPE;
	}

	// check reply handle here
	if (memcmp(reply.handle, &myhandle, 8)) {
		printf("- handle recv\n");
		dump_buffer(reply.handle, 8);
		printf("- handle inside\n");
		dump_buffer((char*) &myhandle, 8);
		warn("proxy error: unknown reply handle");
		return -EPIPE;
	}

	uint32_t error = ntohl(reply.error);
	if (error) {
		warn("proxy error: remote internal, reply state %d", error);
		return -error;
	}

	dbg("recv data %p %zu\n", buf, len);
	ret = net_recv_all_or_error(remotefd, buf, len);
	if (ret < 0) {
		warn("proxy error: read remote data");
		return -EPIPE;
	}

	return 0;
}


void nbd_client_send_disc_request(int remotefd)
{
	struct nbd_request request;
	int ret;

	bzero(&request, sizeof(request));

	request.magic = htonl(NBD_REQUEST_MAGIC);
	request.type = htonl(NBD_CMD_DISC);

	ret = net_send_all(remotefd, &request, sizeof(request));
	if (ret < (ssize_t) sizeof(request))
		warn("sending NBD_DISC failed");
}








/**
 * Returning 0:  request is good.
 * Returning -1: bad request.
 * 		An error is notified the client by using reply.errcode.
 * Returning -2: protocol violation.
 * 	 	The connection is going to be discarded.
 * Returning -3: terminate request.
 */
int nbd_server_recv_request(int clientfd, off_t disksize, uint32_t *iotype_arg, off_t *iofrom_arg,
		size_t *iolen_arg, struct nbd_reply *reply)
{
	struct nbd_request request;
	uint32_t magic  = 0;
	uint32_t iotype = 0;
	uint64_t iofrom = 0;
	uint32_t iolen  = 0;
	int ret;

	bzero(&request, sizeof(request));

	ret = net_recv_all(clientfd, &request, sizeof(request));
	if (check_fin(ret, errno, sizeof(request))) {
		warn("recv_request got FIN, disconnected");
		return -3;
	}

	magic  = ntohl(request.magic);
	iotype = ntohl(request.type);
	iofrom = ntohll(request.from);
	iolen  = ntohl(request.len);

	if (iotype == NBD_CMD_DISC) {
		info("recv_request: disconnect request");
		return -3;
	}

	/* protocol violation */
	if (magic != NBD_REQUEST_MAGIC) {
		warn("recv_request: magic mismatch, %u %u", magic, NBD_REQUEST_MAGIC);
		nbd_request_dump(&request);
		dump_buffer((char *) &request, sizeof(request));
		return -2;
	}


	dbg("%s from %ju (%ju) len %u, ", iotype ? "WRITE" : "READ", iofrom, iofrom / 512U, iolen);

	memcpy(reply->handle, request.handle, sizeof(request.handle));


	/*
	 * nbd-server.c defines the maximum disk size as OFFT_MAX =
	 * ~((off_t)1<<(sizeof(off_t)*8-1)), so it's ok that our disksize is
	 * defined with off_t.
	 **/

	/* bad request */
	if ((iofrom + iolen) > (uint64_t) disksize) {
		warn("error offset exceeds the end of disk, offset %ju (iofrom %ju + iolen %u) disksize %jd",
				(iofrom + iolen), iofrom, iolen, disksize);
		reply->error = htonl(EINVAL);
		return -1;
	}

	*iotype_arg = iotype;
	*iofrom_arg = iofrom;  /* disksize is off_t, so checked already */
	*iolen_arg  = iolen;

	/* io realtime monitor */
	//monitor_access(iofrom, iolen, iotype);

	return 0;
}


const uint64_t XNBDMAGIC = 0x00420281861253LL;

static int nbd_negotiate_with_client_common(int sockfd, off_t exportsize, int readonly)
{
	g_assert(exportsize >= 0);

	uint32_t flags = NBD_FLAG_HAS_FLAGS;
	uint64_t magic = htonll(XNBDMAGIC);
	uint64_t size = htonll(exportsize);

	int ret;

	ret = write(sockfd, INIT_PASSWD, 8);
	if (ret < 0)
		goto err_out;

	ret = write(sockfd, &magic, sizeof(magic));
	if (ret < 0)
		goto err_out;

	ret = write(sockfd, &size, 8);
	if (ret < 0)
		goto err_out;


	if (readonly) {
		info("nbd_negotiate: readonly");
		flags |= NBD_FLAG_READ_ONLY;
	}

	flags = htonl(flags);
	ret = write(sockfd, &flags, 4);
	if (ret < 0)
		goto err_out;

	char zeros[128];
	memset(zeros, '\0', sizeof(zeros));
	ret = write(sockfd, zeros, 124);
	if (ret < 0)
		goto err_out;


	dbg("negotiate done");

	return 0;

err_out:
	warn("negotiation failed"); 
	return -1;
}

int nbd_negotiate_with_client_readonly(int sockfd, off_t exportsize)
{
	return nbd_negotiate_with_client_common(sockfd, exportsize, 1);
}

int nbd_negotiate_with_client(int sockfd, off_t exportsize)
{
	return nbd_negotiate_with_client_common(sockfd, exportsize, 0);
}


#if 0
void nbd_negotiate_with_server(int sockfd, uint64_t *exportsize)
{
	char passwd[8 + 1];
	uint32_t flags = 0;
	uint64_t magic = 0;
	uint64_t size = 0;

	bzero(passwd, sizeof(passwd));

	net_recv_all_or_abort(sockfd, passwd, 8);

	if (strncmp(passwd, INIT_PASSWD, sizeof(INIT_PASSWD)))
			err("password mismatch");

	net_recv_all_or_abort(sockfd, &magic, sizeof(magic));

	if (magic != htonll(XNBDMAGIC))
		err("negotiate magic mismatch");


	net_recv_all_or_abort(sockfd, &size, sizeof(size));

	*exportsize = ntohll(size);
	info("remote size %" PRIu64 "  B (%" PRIu64 " MB)", *exportsize, *exportsize /1024 /1024);

	if ((sizeof(off_t) == 4) && (*exportsize > 2UL * 1024 * 1024 * 1024))
		err("enable large file support!");

	net_recv_all_or_abort(sockfd, &flags, sizeof(flags));

	flags = ntohl(flags);

	char zeros[128];
	net_recv_all_or_abort(sockfd, zeros, 124);
}
#endif


struct nbd_negotiate_pdu {
	char passwd[8];
	uint64_t magic;
	uint64_t size;
	uint32_t flags;
	char padding[124];
} __attribute__((__packed__));


int nbd_negotiate_with_server2(int sockfd, off_t *exportsize, uint32_t *exportflags)
{
	struct nbd_negotiate_pdu pdu;


	int ret = net_recv_all_or_error(sockfd, &pdu, sizeof(pdu));
	if (ret < 0) {
		warn("receiving negotiate header failed");
		return -1;
	}


	if (strncmp(pdu.passwd, INIT_PASSWD, sizeof(INIT_PASSWD)) != 0) {
		warn("password mismatch");
		return -1;
	}


	if (pdu.magic != htonll(XNBDMAGIC)) {
		warn("negotiate magic mismatch");
		return -1;
	}


	uint64_t size = ntohll(pdu.size);
	uint32_t flags = ntohl(pdu.flags);

	info("remote size: %ju bytes (%ju MBytes)", size, size /1024 /1024);


	if (size > OFF_MAX) {
		warn("remote size exceeds a local off_t(%zd bytes) value", sizeof(off_t));
		return -1;
	}



	*exportsize  = (off_t) size;
	*exportflags = flags;

	return 0;
}

off_t nbd_negotiate_with_server(int sockfd)
{
	off_t size;
	uint32_t flags;

	int ret = nbd_negotiate_with_server2(sockfd, &size, &flags);
	if (ret < 0)
		err("negotiate with server");

	return size;
}
