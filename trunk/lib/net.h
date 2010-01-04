/*
 * partially excerpted and modified from usbip.
 *
 * Copyright (C) 2005-2008 Takahiro Hirofuchi
 * Copyright (C) 2008-2009 National Institute of Advanced Industrial Science and Technology
 *
 * Author: Takahiro Hirofuchi
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



/* xnbd_libnet.c */
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
void net_readv_all_or_abort(int fd, struct iovec *iov, unsigned int count);
void check_done(int ret, int errcode);
int check_fin(int ret, int errcode, size_t len);

uint64_t ntohll(uint64_t a);
#define htonll ntohll

int unix_connect(char *path);

#endif
