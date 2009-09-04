/*
 * partially excerpted and modified from usbip.
 *
 * Copyright (C) 2005-2008 Takahiro Hirofuchi
 * Copyright (C) 2008-2009 National Institute of Advanced Industrial Science and Technology
 *
 * Author: Takahiro Hirofuchi
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


static void dump_buffer_main(const char *buff, int bufflen, int all)
{
	int i;

	if (bufflen > 128 && !all) {
		for (i = 0; i< 128; i++) {
			if (i%24 == 0)
				printf("   ");
			printf("%02x ", (unsigned char ) buff[i]);
			if (i%4 == 3) printf("| ");
			if (i%24 == 23) printf("\n");
		}
		printf("... (%d byte)\n", bufflen);
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

void dump_buffer_all(const char *buff, int bufflen)
{
	dump_buffer_main(buff, bufflen, 1);
}

void dump_buffer(const char *buff, int bufflen)
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

uint64_t get_disksize(int fd) {
	struct stat st;
	uint64_t disksize = 0;
	int ret;


	dbg("get disk size by fstat\n");
	bzero(&st, sizeof(struct stat));

	ret = fstat(fd, &st);
	if (ret < 0) {
		if (errno == EOVERFLOW)
			err("enable 64bit offset support");
	}


	/* device file may return st_size == 0 */
	if (S_ISREG(st.st_mode)) {
		disksize = (uint64_t) st.st_size;
		dbg("st_size %llu", (uint64_t) disksize);
		return disksize;

	} else if (S_ISBLK(st.st_mode)) {
		off_t offset = 0;

		dbg("looking for fd size with lseek SEEK_END\n");
		offset = lseek(fd, 0, SEEK_END);
		if (offset < 0)
			err("lseek failed: %d", errno);

		disksize = (uint64_t) offset;

		return disksize;

	} else {
		err("file type %d not supported", st.st_mode);
	}


	err("failed to detect disk size");

	/* NOT REACHED */
	return 0;
}

void calc_block_index(const uint32_t blocksize, uint64_t iofrom, uint32_t iolen, uint32_t *index_start, uint32_t *index_end)
{
	uint32_t block_index_start = iofrom / blocksize;
	uint32_t block_index_end;

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

int put_line(int fd, char *msg)
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
