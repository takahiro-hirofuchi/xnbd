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
	info(" request.from  %llu %llu", request->from, ntohll(request->from));
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



const char myhandle[8] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

int send_read_request(int remotefd, uint64_t iofrom, uint32_t len)
{
	struct nbd_request request;
	int ret;

	dbg("sending request of iotype %s iofrom %llu len %u",
			"read", iofrom, len);

	bzero(&request, sizeof(request));

	request.magic = htonl(NBD_REQUEST_MAGIC);
	request.type = htonl(NBD_CMD_READ);
	request.from = htonll(iofrom);
	request.len = htonl(len);

	/* handle is 'char handle[8]' */
	memcpy(request.handle, myhandle, 8);

	ret = net_send_all(remotefd, &request, sizeof(request));
	if (ret < (int) sizeof(request)) {
		warn("send header");
		return -1;
	}

	return 0;
}


int recv_read_reply(int remotefd, char *buf, uint32_t len)
{
	struct nbd_reply reply;
	int ret;

	dbg("now reciving read reply");

	if (!buf)
		err("bug");


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
	if (memcmp(reply.handle, myhandle, 8)) {
		printf("- handle recv\n");
		dump_buffer(reply.handle, 8);
		printf("- handle inside\n");
		dump_buffer(myhandle, 8);
		warn("proxy error: unknown reply handle");
		return -EPIPE;
	}

	uint32_t error = ntohl(reply.error);
	if (error) {
		warn("proxy error: remote internal, reply state %d", error);
		return -error;
	}

	dbg("recv data %p %u\n", buf, len);
	ret = net_recv_all_or_error(remotefd, buf, len);
	if (ret < 0) {
		warn("proxy error: read remote data");
		return -EPIPE;
	}

	return 0;
}


void send_disc_request(int remotefd)
{
	struct nbd_request request;
	int ret;

	bzero(&request, sizeof(request));

	request.magic = htonl(NBD_REQUEST_MAGIC);
	request.type = htonl(NBD_CMD_DISC);

	ret = net_send_all(remotefd, &request, sizeof(request));
	if (ret < (int) sizeof(request))
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
int recv_request(int clientfd, uint64_t disksize, uint32_t *iotype_arg, uint64_t *iofrom_arg,
		uint32_t *iolen_arg, struct nbd_reply *reply)
{
	int csock = clientfd;
	uint64_t exportsize = disksize;

	struct nbd_request request;
	uint32_t magic  = 0;
	uint32_t iotype = 0;
	uint64_t iofrom = 0;
	uint32_t iolen  = 0;
	int ret;

	bzero(&request, sizeof(request));

	ret = net_recv_all(csock, &request, sizeof(request));
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

	/* protocol violation */
	if (iolen > (BUFSIZE - sizeof(struct nbd_reply))) {
		warn("too big request size");
		return -2;
	}


	dbg("%s from %Lu (%Lu) len %d, ", iotype ? "WRITE" : "READ", iofrom, iofrom / 512, iolen);

	memcpy(reply->handle, request.handle, sizeof(request.handle));


	/* bad request */
	if ((iofrom + iolen) > (OFFT_MAX)) {
		warn("error maxoffset OFFT_MAX %llu", OFFT_MAX);
		reply->error = htonl(EINVAL);
		return -1;
	}

	/* bad request */
	if ((iofrom + iolen) > exportsize) {
		warn("error offset exceeds the end of disk, offset %llu (iofrom %llu + iolen %u) disksize %llu",
				(iofrom + iolen), iofrom, iolen, exportsize);
		reply->error = htonl(EINVAL);
		return -1;
	}

	*iotype_arg = iotype;
	*iofrom_arg = iofrom;
	*iolen_arg  = iolen;

	/* io realtime monitor */
	//monitor_access(iofrom, iolen, iotype);

	return 0;
}


const uint64_t XNBDMAGIC = 0x00420281861253LL;

static int nbd_negotiate_with_client_common(int sockfd, uint64_t exportsize, int readonly)
{
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


	if (readonly)
		flags |= NBD_FLAG_READ_ONLY;

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

int nbd_negotiate_with_client_readonly(int sockfd, uint64_t exportsize)
{
	return nbd_negotiate_with_client_common(sockfd, exportsize, 1);
}

int nbd_negotiate_with_client(int sockfd, uint64_t exportsize)
{
	return nbd_negotiate_with_client_common(sockfd, exportsize, 0);
}


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

	return;
}
