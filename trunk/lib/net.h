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

#ifndef LIB_XNBD_NET_H
#define LIB_XNBD_NET_H

#include "common.h"


#include <unistd.h>

/* writev */
#include <sys/uio.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/un.h>

#include <errno.h>
#include <string.h>
#include <stdio.h>

#include <stdlib.h>


#define MAXLISTENSOCK 20
unsigned int net_listen_all_addrinfo(struct addrinfo *ai_head, int lsock[]);
int net_accept(int lsock);
struct addrinfo *net_getaddrinfo(char *host, int port, int ai_family);
int net_set_reuseaddr(int sockfd);
int net_set_nodelay(int sockfd);
int net_tcp_connect(const char *hostname, const char *service);
int net_writev(int fd, struct iovec *iov, int count);
int net_readv(int fd, struct iovec *iov, int count);
ssize_t net_recv(int sockfd, void *buff, size_t bufflen);
ssize_t net_send(int sockfd, void *buff, size_t bufflen);
int net_writev_all(int fd, struct iovec *iov, int count);
int net_readv_all(int fd, struct iovec *iov, int count);
ssize_t net_recv_all(int sockfd, void *buff, size_t bufflen);
void net_recv_all_or_abort(int sockfd, void *buff, size_t bufflen);
int net_recv_all_or_error(int sockfd, void *buff, size_t bufflen);
ssize_t net_send_all(int sockfd, void *buff, size_t bufflen);
void net_send_all_or_abort(int sockfd, void *buff, size_t bufflen);
int net_send_all_or_error(int sockfd, void *buff, size_t bufflen);
void net_writev_all_or_abort(int fd, struct iovec *iov, unsigned int count);
int net_writev_all_or_error(int fd, struct iovec *iov, unsigned int count);
void net_readv_all_or_abort(int fd, struct iovec *iov, unsigned int count);
int net_readv_all_or_error(int fd, struct iovec *iov, unsigned int count);
void check_done(int ret, int errcode);
int check_fin(int ret, int errcode, size_t len);

#include <endian.h>
#define ntohll(x) be64toh(x)
#define htonll(x) htobe64(x)

int unix_connect(const char *path);
int unix_send_fd(int socket, int fd);
int unix_recv_fd(int socket);

#endif
