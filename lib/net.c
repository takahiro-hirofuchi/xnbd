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

#include "net.h"


/* ------------------------------------------------------------------------------------------ */

static char *get_nameinfo_string(struct addrinfo *ai)
{
	int ret;
	char hbuf[NI_MAXHOST];
	char sbuf[NI_MAXSERV];

	ret = getnameinfo(ai->ai_addr, ai->ai_addrlen, hbuf, sizeof(hbuf),
			sbuf, sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV);
	if (ret)
		warn("getnameinfo failed, %s", gai_strerror(ret));

	const char *type = "unknown_ai_socktype";

	if (ai->ai_protocol == IPPROTO_TCP)
		type = "TCP";
	else if (ai->ai_protocol == IPPROTO_UDP)
		type = "UDP";
	else if (ai->ai_protocol == IPPROTO_SCTP)
		type = "SCTP";
	else if (ai->ai_protocol == IPPROTO_DCCP)
		type = "DCCP";

	if (ai->ai_family == AF_INET)
		return g_strdup_printf("%s:%s,%s", hbuf, sbuf, type);
	else
		return g_strdup_printf("[%s]:%s,%s", hbuf, sbuf, type);
}

struct addrinfo *net_getaddrinfo(char *host, int port, int ai_family, int socktype, int proto)
{
	int ret;
	struct addrinfo hints, *ai_head;
	char portstr[NI_MAXSERV];

	memset(&hints, 0, sizeof(hints));

	hints.ai_family   = ai_family;
	hints.ai_socktype = socktype; /* SOCK_STREAM */
	hints.ai_flags    = AI_PASSIVE;
	hints.ai_protocol = proto; /* IPPROTO_TCP */

	snprintf(portstr, sizeof(portstr), "%d", port);

	ret = getaddrinfo(host, portstr, &hints, &ai_head);
	if (ret)
		g_error("getaddrinfo() failed %s: %s", portstr, gai_strerror(ret));

	return ai_head;
}

unsigned int net_create_server_sockets(struct addrinfo *ai_head, int *fds, size_t nfds)
{
	struct addrinfo *ai;
	size_t index = 0;		/* number of sockets */

	for (ai = ai_head; ai != NULL; ai = ai->ai_next) {
		if (index >= nfds) {
			info("skip other addresses");
			break;
		}

		char *name = get_nameinfo_string(ai);
		int reuseaddr = 0;
		int tcpnodelay = 0;
		int keepalive = 0;


		int sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sockfd < 0)  {
			/* if the host does not support ipv6, this might happen. */
			warn("socket(%s) failed, %m", name);
			g_free(name);
			continue;
		}



		net_set_reuseaddr(sockfd);
		reuseaddr = 1;

		if (ai->ai_socktype == SOCK_STREAM && ai->ai_protocol == IPPROTO_TCP) {
			net_set_nodelay(sockfd);
			tcpnodelay = 1;
			net_set_keepalive(sockfd);
			keepalive = 1;
		}

		if (ai->ai_family == AF_INET6)
			net_set_bindv6only(sockfd);

		/* just for double check */
		if (sockfd >= FD_SETSIZE)
			warn("select/poll() may fail because sockfd (%d) >= FD_SETSIZE.", sockfd);

		int ret = bind(sockfd, ai->ai_addr, ai->ai_addrlen);
		if (ret < 0)
			g_error("bind(%s) failed, %m", name);


		if ((ai->ai_socktype == SOCK_STREAM && ai->ai_protocol == IPPROTO_TCP) ||
				(ai->ai_socktype == SOCK_DCCP && ai->ai_protocol == IPPROTO_DCCP)) {
			ret = listen(sockfd, SOMAXCONN);
			if (ret < 0)
				g_error("listen(%s) failed, %m", name);
		}

		GString *gs = g_string_new(NULL);
		g_string_append_printf(gs, "server %s,fd=%d", name, sockfd);
		if (reuseaddr)
			g_string_append(gs, ",reuseaddr");
		if (tcpnodelay)
			g_string_append(gs, ",nodelay");
		if (keepalive)
			g_string_append(gs, ",keepalive");

		info("%s", gs->str);
		g_string_free(gs, TRUE);



		fds[index] = sockfd;
		index++;

		g_free(name);
	}

	if (index == 0)
		warn("no server sockets created");

	return index;
}


int net_accept(int lsock)
{
	int csock;
	struct sockaddr_storage ss;
	socklen_t len = sizeof(ss);
	char host[NI_MAXHOST], port[NI_MAXSERV];
	int ret;

	memset(&ss, 0, sizeof(ss));

	csock = accept(lsock, (struct sockaddr *) &ss, &len);
	if (csock < 0) {
		warn("accept failed, fd %d, %s (%d)", csock, strerror(errno), errno);
		return -1;
	}

	ret = getnameinfo((struct sockaddr *) &ss, len,
			host, sizeof(host), port, sizeof(port),
			(NI_NUMERICHOST | NI_NUMERICSERV));
	if (ret)
		warn("getnameinfo failed, %s", gai_strerror(ret));

	if (ss.ss_family == AF_INET)
		info("connected from %s:%s", host, port);
	else if (ss.ss_family == AF_INET6)
		info("connected from [%s]:%s", host, port);
	else if (ss.ss_family == AF_UNIX)
		// info("connected at %s", ((struct sockaddr_un *) &ss)->sun_path);
		info("connected (unix)");
	else
		info("connected (unknown pf)");

	return csock;
}

int net_set_reuseaddr(int sockfd)
{
	const int val = 1;
	int ret;

	ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	if (ret < 0)
		warn("setsockopt SO_REUSEADDR failed");

	return ret;
}

int net_set_nodelay(int sockfd)
{
	const int val = 1;
	int ret;

	ret = setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
	if (ret < 0)
		warn("setsockopt TCP_NODELAY failed");

	return ret;
}

int net_set_bindv6only(int sockfd)
{
	const int val = 1;
	int ret;

	ret = setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));
	if (ret < 0)
		warn("setsockopt IPV6_V6ONLY failed");

	return ret;
}

int net_set_keepalive(int sockfd)
{
	const int val = 1;
	int ret;

	ret = setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));
	if (ret < 0)
		warn("setsockopt SO_KEEPALIVE failed");

	return ret;
}

/* IPv6 Ready */
int net_connect(const char *hostname, const char *service, int socktype, int proto)
{
	struct addrinfo hints, *ai_head;
	int sockfd;
	int found = 0;


	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = socktype;
	hints.ai_protocol = proto;

	/* get all possible addresses */
	int ret = getaddrinfo(hostname, service, &hints, &ai_head);
	if (ret) {
		warn("getaddrinfo failed, %s %s: %s", hostname, service, gai_strerror(ret));
		return -1;
	}

	/* try all the addresses */
	for (struct addrinfo *ai = ai_head; ai != NULL; ai = ai->ai_next) {
		char *nameinfo = get_nameinfo_string(ai);

		dbg("trying %s", nameinfo);

		sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sockfd < 0) {
			warn("socket() failed, %m");
			goto cleanup;
		}

		if (proto == IPPROTO_TCP) {
			net_set_nodelay(sockfd);
			net_set_keepalive(sockfd);
		}


		ret = connect(sockfd, ai->ai_addr, ai->ai_addrlen);
		if (ret < 0) {
			dbg("connect() %s failed, %m", nameinfo);
			close(sockfd);
			goto cleanup;
		}

		/* connected */
		found = 1;
		info("connected to %s", nameinfo);

cleanup:
		g_free(nameinfo);

		if (found)
			break;
		/* continue if not found */
	}


	freeaddrinfo(ai_head);

	if (found) {
		return sockfd;
	} else {
		dbg("%s:%s, %s", hostname, service, "no destination to connect to");
		return -1;
	}
}




/*
 * Write all data surely.
 * It fails when
 *    - writev() detects the arrival of TCP_RST
 *      => return -1 with errno
 *    - an error occurs
 *      => return -1 with errno
 *
 * Read all data surely.
 * It fails when
 *    - readv() detects EOF or the arrival of TCP_FIN
 *      => return read bytes which are less than a request size
 *    - the arrival of TCP_RST
 *      => return -1 with errno
 *    - when an error occurs.
 *      => return -1 with errno
 *
 * In the case of read, a caller can detect FIN or EOF; a return code is less
 * than a request size (the total of iov[i].iov_len). If a request size is
 * zero, a caller cannot detect FIN or EOF.
 */
static int net_iov_all(int fd, struct iovec *iov, int count, int reading)
{
	int next_count = count;
	struct iovec *next_iov = iov;

	const char *mode = reading ? "readv" : "writev";


	/* all bytes we have read */
	ssize_t total  = 0;


#ifdef XNBD_DEBUG
	int total_expected_size = 0;
	for (int i = 0; i < count; i++)
		total_expected_size += iov[i].iov_len;

	dbg("net_iov start %s, count %d expect %d",
			mode, count, total_expected_size);
#endif

	for (;;) {
		ssize_t sent = 0;
		int expected = 0;
		int do_next = 0;

		dbg("perform %d iovec(s)", next_count);

#ifdef XNBD_DEBUG
		/* check readv/write is broken or not */
		struct iovec *iov_org = g_malloc(sizeof(struct iovec) * count);

		for (int i = 0; i < next_count; i++) {
			iov_org[i].iov_base = next_iov[i].iov_base;
			iov_org[i].iov_len  = next_iov[i].iov_len;
		}
#endif

		if (reading)
			sent = readv(fd, next_iov, next_count);
		else
			sent = writev(fd, next_iov, next_count);

#ifdef XNBD_DEBUG
		for (int i = 0; i < next_count; i++) {
			if (iov_org[i].iov_base != next_iov[i].iov_base ||
				iov_org[i].iov_len != next_iov[i].iov_len) {
				warn("iov_org[%d].iov_base %p, next_iov[%d].iov_base %p",
						i, iov_org[i].iov_base, i, next_iov[i].iov_base);
				warn("iov_org[%d].iov_len %zd, next_iov[%d].iov_len %zd",
						i, iov_org[i].iov_len, i, next_iov[i].iov_len);
			}
		}

		g_free(iov_org);
#endif

		if (sent == 0) {
			info("%s() returned 0 (fd %d)", mode, fd);
			/* writev returns 0,
			 *   if an I/O size is zero
			 * readv returns 0,
			 *   if and I/O size is zero
			 *   if it got FIN
			 *   if it is EOF
			 */
			return total;
		}

		if (sent == -1) {
			if (errno == ECONNRESET)
				info("received TCP_RST (fd %d)", fd);
			else if (errno == EPIPE)
				info("raised EPIPE (fd %d)", fd);
			else
				warn("%s error %s (%d) (fd %d)", mode, strerror(errno), errno, fd);

			return -1;
		}

		total += sent;


		for (int i = 0; i < next_count; i++) {
			expected += next_iov[i].iov_len;
			if (sent < expected) {
				dbg("partial io (count %d/%d), %s %zd bytes", i, next_count,
						reading ? "read" : "sent", sent);
				/* we have the rest of sent data from iov[i] */

				int rest_in_block = expected - sent;
				// int sent_in_block = iov[i].iov_len - rest_in_block;
				int sent_in_block = next_iov[i].iov_len - rest_in_block;
				next_iov[i].iov_base = (char *)next_iov[i].iov_base + sent_in_block;
				next_iov[i].iov_len  = rest_in_block;

				/* next iovec */
				next_iov = &next_iov[i];
				next_count -= i;
				do_next = 1;
				break;
			}
		}

		if (!do_next)
			break;
	}


#ifdef XNBD_DEBUG
	if (total_expected_size != total)
		dbg("total_expected_size %d, total %zd", total_expected_size, total);
#endif

	dbg("net_iov end %s", mode);

	return total;
}

int net_writev_all(int fd, struct iovec *iov, int count)
{
	dbg("net_writev");
	return net_iov_all(fd, iov, count, 0);
}

int net_readv_all(int fd, struct iovec *iov, int count)
{
	dbg("net_readv");
	return net_iov_all(fd, iov, count, 1);
}

ssize_t net_send_all(int sockfd, const void *buff, size_t bufflen)
{
	struct iovec iov[1];

	iov[0].iov_base = (void *) buff;
	iov[0].iov_len  = bufflen;

	return net_iov_all(sockfd, iov, 1, 0);
}

ssize_t net_recv_all(int sockfd, void *buff, size_t bufflen)
{
	struct iovec iov[1];

	iov[0].iov_base = buff;
	iov[0].iov_len  = bufflen;

	return net_iov_all(sockfd, iov, 1, 1);
}

/*
 * check return code of net_iov_all() for write.
 * check return code of normal read() (i.e., just read available data).
 * return, if all data was written
 *
 * if an error was detected, exit() or abort.
 */
void check_done(int ret, int errcode)
{
	/* return code of net_iov_all() for write is >=0 (success) or -1 (failure) */
	if (ret == -1)  {
		if (errcode == ECONNRESET || errcode == EPIPE) {
			/* TODO: use err() ? */
			info("got RST. abort");
			exit(EXIT_SUCCESS);
		}

		info("unknown err");

		err("xmit: %s (%d)", strerror(errcode), errcode);
	} else if (ret >= 0)
		return;


	err("not reached");
}


/*
 * check return code of net_iov_all() for read.
 * return 1,  if FIN or EOF is detected.
 * return 0,  if all data was read.
 *
 * if an error was detected, exit() or abort.
 */
int check_fin(int ret, int errcode, size_t len)
{
	if (ret == -1)  {
		if (errcode == ECONNRESET || errcode == EPIPE) {
			/* TODO: use err() ? or return 1 */
			info("got RST. abort");
			exit(EXIT_SUCCESS);
		}

		err("xmit: %s (%d)", strerror(errcode), errcode);

	} else if (ret == 0) {
		if (len > 0)
			return 1;  // FIN
		else
			err("len must be larger than 0");

	} else if (ret > 0) {
		/* performed size was returned */
		if (ret < (int) len)
			return 1;  // FIN
		else if (ret == (int) len)
			return 0;  // requested size was performed
		else
			err("len mismatch");
	}


	err("not reached");

	return -1;
}

void net_writev_all_or_abort(int fd, struct iovec *iov, unsigned int count)
{
	int ret = net_writev_all(fd, iov, count);
	check_done(ret, errno);
}

int net_writev_all_or_error(int fd, struct iovec *iov, unsigned int count)
{
	size_t bufflen = 0;
	for (unsigned int i = 0; i < count; i++)
		bufflen += iov[i].iov_len;

	int ret = net_writev_all(fd, iov, count);
	if (ret != (int) bufflen)
		return -1;

	/* if failed to send all data, return -1 */

	return ret;
}

void net_send_all_or_abort(int sockfd, const void *buff, size_t bufflen)
{
	int ret = net_send_all(sockfd, buff, bufflen);
	check_done(ret, errno);

	/* if failed to send all data, exit */
}

int net_send_all_or_error(int sockfd, const void *buff, size_t bufflen)
{
	int ret = net_send_all(sockfd, buff, bufflen);
	if (ret != (int) bufflen)
		return -1;

	/* if failed to send all data, return -1 */

	return ret;
}

void net_readv_all_or_abort(int fd, struct iovec *iov, unsigned int count)
{
	size_t bufflen = 0;
	for (unsigned int i = 0; i < count; i++)
		bufflen += iov[i].iov_len;

	int ret = net_readv_all(fd, iov, count);
	if (check_fin(ret, errno, bufflen))
		err("sockfd (%d) closed", fd);
}

int net_readv_all_or_error(int fd, struct iovec *iov, unsigned int count)
{
	size_t bufflen = 0;
	for (unsigned int i = 0; i < count; i++)
		bufflen += iov[i].iov_len;

	int ret = net_readv_all(fd, iov, count);
	if (ret != (int) bufflen)
		return -1;

	return ret;
}

void net_recv_all_or_abort(int sockfd, void *buff, size_t bufflen)
{
	int ret = net_recv_all(sockfd, buff, bufflen);
	if (check_fin(ret, errno, bufflen))
		err("sockfd (%d) closed", sockfd);

	/* when an error or FIN is detected, exit */
}

int net_recv_all_or_error(int sockfd, void *buff, size_t bufflen)
{
	int ret = net_recv_all(sockfd, buff, bufflen);
	if (ret != (int) bufflen)
		return -1;

	/* when an error or FIN is detected, return -1 */

	return ret;
}

int unix_connect(const char *path)
{
	int fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0)
		err("socket %m");

	struct sockaddr_un cliaddr;
	cliaddr.sun_family = AF_LOCAL;
	g_strlcpy(cliaddr.sun_path, path, sizeof(cliaddr.sun_path));

	int ret = connect(fd, (struct sockaddr *) &cliaddr, sizeof(cliaddr));
	if (ret < 0)
		err("connect %m");

	return fd;
}

int unix_send_fd(int socket, int fd)
{
	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));

	struct iovec iov[1];
	iov[0].iov_base = (char *) "";
	iov[0].iov_len = 1;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;


	char data_buf[CMSG_SPACE(sizeof(fd))];

	msg.msg_control = data_buf;
	msg.msg_controllen = sizeof(data_buf);

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type  = SCM_RIGHTS;
	cmsg->cmsg_len   = CMSG_LEN(sizeof(fd));

	memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));

	msg.msg_controllen = cmsg->cmsg_len;


	int ret = sendmsg(socket, &msg, 0);
	if (ret == -1)
		warn("send_fd, %m");
	else if (ret == 0)
		warn("send_fd, peer closed");


	return ret;
};


int unix_recv_fd(int socket)
{
	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));

	int fd;
	char buf[1];

	struct iovec iov[1];
	iov[0].iov_base = buf;
	iov[0].iov_len = sizeof(buf);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	char data_buf[CMSG_SPACE(sizeof(fd))];

	msg.msg_control = data_buf;
	msg.msg_controllen = sizeof(data_buf);

	int ret = recvmsg(socket, &msg, 0);
	if (ret == -1)
		err("recv_fd, %m");
	else if (ret == 0)
		err("recv_fd, peer closed");


	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg)
		err("no cmsghdr");

	if (cmsg->cmsg_len == CMSG_LEN(sizeof(fd))
		&& cmsg->cmsg_level == SOL_SOCKET
		&& cmsg->cmsg_type == SCM_RIGHTS) {

		memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
	} else
		err("no descriptor");


	info("fd %d received", fd);


	return fd;
}
