/* 
 * Copyright (C) 2008-2010 National Institute of Advanced Industrial Science and Technology
 *
 * Author: Takahiro Hirofuchi
 */
#ifndef LIB_XNBD_NBD_H
#define LIB_XNBD_NBD_H

#include "common.h"
#include "net.h"
#include "io.h"
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>


/* ------------------------------------------------------------------------------------------ */
/* ------------------------------------------------------------------------------------------ */

/* this part comes from nbd-2.9.11 */

/* excerpt from the original nbd.h */
/*
 * 1999 Copyright (C) Pavel Machek, pavel@ucw.cz. This code is GPL.
 * 1999/11/04 Copyright (C) 1999 VMware, Inc. (Regis "HPReg" Duchesne)
 *            Made nbd_end_request() use the io_request_lock
 * 2001 Copyright (C) Steven Whitehouse
 *            New nbd_end_request() for compatibility with new linux block
 *            layer code.
 * 2003/06/24 Louis D. Langholtz <ldl@aros.net>
 *            Removed unneeded blksize_bits field from nbd_device struct.
 *            Cleanup PARANOIA usage & code.
 * 2004/02/19 Paul Clements
 *            Removed PARANOIA, plus various cleanup and comments
 */
#define NBD_REQUEST_MAGIC 0x25609513
#define NBD_REPLY_MAGIC 0x67446698

/*
 * This is the packet used for communication between client and
 * server. All data are in network byte order.
 */
struct nbd_request {
	uint32_t magic;
	uint32_t type;       /* == READ || == WRITE  */
	char handle[8];
	uint64_t from;
	uint32_t len;
} __attribute__((packed));

/*
 * This is the reply packet that nbd-server sends back to the client after
 * it has completed an I/O request (or an error occurs).
 */
struct nbd_reply {
	uint32_t magic;
	uint32_t error;              /* 0 = ok, else error   */
	char handle[8];         /* handle you got from request  */
};


/* end excerpt from the original nbd */

/* ------------------------------------------------------------------------------------------ */
/* ------------------------------------------------------------------------------------------ */



enum {
	NBD_CMD_READ = 0,
	NBD_CMD_WRITE = 1,
	NBD_CMD_DISC = 2,

	NBD_CMD_BGCOPY = 3,

	NBD_CMD_READ_COMPRESS = 4,
	NBD_CMD_READ_COMPRESS_LZO = 5
};


int nbd_negotiate_with_client(int sockfd, off_t exportsize);
int nbd_negotiate_with_client_readonly(int sockfd, off_t exportsize);
off_t nbd_negotiate_with_server(int sockfd);
int nbd_negotiate_with_server2(int sockfd, off_t *exportsize, uint32_t *exportflags);

#define INIT_PASSWD "NBDMAGIC"

/* Flags used between the client and server */
#define NBD_FLAG_HAS_FLAGS      (1 << 0)        /* Flags are there */
#define NBD_FLAG_READ_ONLY      (1 << 1)        /* Device is read-only */






/* for debug */
void nbd_request_dump(struct nbd_request *request);
void nbd_reply_dump(struct nbd_reply *reply);


int  nbd_server_recv_request(int clientfd, off_t disksize, uint32_t *iotype_arg, off_t *iofrom_arg,
		size_t *iolen_arg, struct nbd_reply *reply);
int nbd_client_send_request_header(int remotefd, uint32_t iotype, off_t iofrom, size_t len, uint64_t handle);
int  nbd_client_send_read_request(int remotefd, off_t iofrom, size_t len);
void nbd_client_send_disc_request(int remotefd);
int nbd_client_recv_read_reply_iov(int remotefd, struct iovec *iov, unsigned int count);
int  nbd_client_recv_read_reply(int remotefd, char *buf, size_t len);
int nbd_client_recv_header(int remotefd);

#endif
