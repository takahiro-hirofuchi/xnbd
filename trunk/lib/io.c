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

#include "io.h"

static void io_all(int fd, void *buf, size_t len, int read_ops)
{
	int   next_len = len;
	void *next_buf = buf;

	char *mode = read_ops ? "read" : "write";
	size_t total = 0;

	for (;;) {
		int ret = 0;

		if (read_ops)
			ret = read(fd, next_buf, next_len);
		else
			ret = write(fd, next_buf, next_len);

		if (ret == 0)
			g_message("%s() returned 0 (fd %d)", mode, fd);


		if (ret == -1)
			err("%s error %s (%d) (fd %d)", mode, strerror(errno), errno, fd);

		total += ret;

		next_len -= ret;
		next_buf += ret;

		if (total == len)
			break;
	}
}

void read_all(int fd, void *buf, size_t len)
{
	io_all(fd, buf, len, 1);
}

void write_all(int fd, void *buf, size_t len)
{
	io_all(fd, buf, len, 0);
}


static void dump_buffer_main(const char *buff, size_t bufflen, int all)
{
	unsigned int i;

	if (bufflen > 128 && !all) {
		for (i = 0; i< 128; i++) {
			if (i%24 == 0)
				printf("   ");
			printf("%02x ", (unsigned char ) buff[i]);
			if (i%4 == 3) printf("| ");
			if (i%24 == 23) printf("\n");
		}
		printf("... (%zu byte)\n", bufflen);
		return;
	}

	for (i = 0; i< bufflen; i++) {
		if (i%24 == 0)
			printf("%4d|| ", i);
		printf("%02x ", (unsigned char ) buff[i]);
		if (i%4 == 3)
			printf("| ");
		if (i%24 == 23)
			printf("\n");
	}
	printf("\n");

}

void dump_buffer_all(const char *buff, size_t bufflen)
{
	dump_buffer_main(buff, bufflen, 1);
}

void dump_buffer(const char *buff, size_t bufflen)
{
	dump_buffer_main(buff, bufflen, 0);
}

pthread_t pthread_create_or_abort(void * (*start_routine)(void *), void *arg)
{
	pthread_t tid;

	int ret = pthread_create(&tid, NULL, start_routine, arg);
	if (ret < 0)
		err("create thread");

	return tid;
}

pid_t fork_or_abort(void)
{
	pid_t pid = fork();
	if (pid < 0)
		err("fork() %m");

	return pid;
}

off_t get_disksize(int fd) {
	struct stat st;
	off_t disksize = 0;


	int ret = fstat(fd, &st);
	if (ret < 0) {
		if (errno == EOVERFLOW)
			err("enable 64bit offset support");
	}

	/* device file may return st_size == 0 */
	if (S_ISREG(st.st_mode)) {
		disksize = st.st_size;

		return disksize;

	} else if (S_ISBLK(st.st_mode)) {
		disksize = lseek(fd, 0, SEEK_END);
		if (disksize < 0)
			err("lseek failed: %d", errno);

		return disksize;

	} else if (S_ISCHR(st.st_mode)) {
		/* for our special device */
		if (major(st.st_rdev) == 259)
			return lseek(fd, 0, SEEK_END);

	} else
		err("file type %d not supported", st.st_mode);


	err("failed to detect disk size");

	/* NOT REACHED */
	return 0;
}

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

off_t get_disksize_of_path(char *path)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		err("disk open, %s", path);

	off_t disksize = get_disksize(fd);

	close(fd);

	return disksize;
}

void calc_block_index(const unsigned int blocksize, const off_t iofrom, const size_t iolen, unsigned long *index_start, unsigned long *index_end)
{
	unsigned long block_index_start = iofrom / blocksize;
	unsigned long block_index_end;

	if ((iofrom + iolen) % blocksize == 0) {
		block_index_end   = (iofrom + iolen) / blocksize - 1;
	} else {
		block_index_end   = (iofrom + iolen) / blocksize;
	}

	*index_start = block_index_start;
	*index_end   = block_index_end;
}

char *get_line(int fd)
{
	int found_eol = 0;
#define MAX_LINE 100
	char *line = g_malloc0(MAX_LINE);

	dbg("start get_line");

	for (int i = 0; i < MAX_LINE; i++) {
		char ch = '0';

		int ret = read(fd, &ch, 1);
		if (ret == 0) {
			info("get_line: peer closed");
			goto err_eof;
		} else if (ret == -1) {
			if (errno == ECONNRESET)
				info("get_line: peer closed (%m)");
			else
				warn("get_line: err %d (%m)", errno);
			goto err;
		}

		dbg("  :%c", ch);

		if (ch == '\n') {
			found_eol = 1;
			break;
		}

		line[i] = ch;
	}

	if (!found_eol) {
		warn("no eol found before MAX_LINE(%d)", MAX_LINE);
		goto err;
	}

	dbg("end get_line");

	/* this returned buffer must be freeed */

	return line;

err_eof:
err:
	g_free(line);
	return NULL;
}

int put_line(int fd, const char *msg)
{
	char line[MAX_LINE]; /* msg + '\n' + '\0' */

	if (strnlen(msg, MAX_LINE - 2) == (MAX_LINE - 2)) {
		warn("too large msg for a line");
		return -1;
	}

	sprintf(line, "%s\n", msg);

	dbg("put_line [%s]", msg);

	int ret = net_send_all_or_error(fd, line, strlen(line));
	if (ret < 0)
		return -1;

	return 0;
}

void sigmask_all(void)
{
	sigset_t sig;
	int ret = sigfillset(&sig);
	if (ret < 0) 
		err("sigfillset");

	ret = pthread_sigmask(SIG_SETMASK, &sig, NULL);
	if (ret < 0)
		err("sigmask");
}

int poll_data_and_event(int datafd, int event_listener_fd)
{
	struct pollfd eventfds[2];

	dbg("datafd %d event_listener_fd %d", datafd, event_listener_fd);
	for (;;) {
		eventfds[0].fd = datafd;
		eventfds[0].events = POLLRDNORM | POLLRDHUP;
		eventfds[1].fd = event_listener_fd;
		eventfds[1].events = POLLRDNORM | POLLRDHUP;

		int nready = poll(eventfds, 2, -1);
		if (nready == -1) {
			if (errno == EINTR) {
				info("polling signal cached");
				return -1;
			} else
				err("polling, %s, (%d)", strerror(errno), errno);
		}


		if (eventfds[1].revents & (POLLRDNORM | POLLRDHUP)) {
			info("notified");
			return -1;
		}

		if (eventfds[0].revents & (POLLRDNORM | POLLRDHUP)) {
			/* request arrived */
			return 0;
		}
	}
}

void get_event_connecter(int *notifier, int *listener)
{
	int pipefds[2];
	int ret = pipe(pipefds);
	if (ret == -1)
		err("pipe, %m");

	*notifier = pipefds[1];
	*listener = pipefds[0];
}
