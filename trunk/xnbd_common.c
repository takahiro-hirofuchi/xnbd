/* 
 * Copyright (C) 2008-2009 National Institute of Advanced Industrial Science and Technology
 */
#include "xnbd.h"

const uint32_t CBLOCKSIZE = 4096;
unsigned int PAGESIZE = 4096;








void get_io_range_index(uint64_t iofrom, uint32_t iolen, uint32_t *index_start, uint32_t *index_end)
{
	calc_block_index(CBLOCKSIZE, iofrom, iolen, index_start, index_end);
}





void *mmap_iorange(struct xnbd_info *xnbd, int fd, uint64_t iofrom, uint32_t iolen, char **mmaped_buf, uint32_t *mmaped_len, uint64_t *mmaped_offset)
{
	uint32_t index_start, index_end;
	char *buf;

	get_io_range_index(iofrom, iolen, &index_start, &index_end);

	//dbg("iofrom %llu iofrom + iolen %llu", iofrom, iofrom + iolen);
	//dbg("block_index_start %u end %u", index_start, index_end);

	/* (uint64_t) casting is essential !!! */
	uint64_t mapping_start  = ((uint64_t) index_start) * CBLOCKSIZE;
	uint32_t mapping_length = (index_end - index_start + 1) * CBLOCKSIZE;

	//dbg("%u * %u = %llu", index_start, CBLOCKSIZE, mapping_start);

	//dbg("mmapping_start %llu mapping_end %llu mapping_length %u", 
	//		mapping_start, mapping_start + mapping_length,
	//		mapping_length);

	if ((mapping_start + mapping_length) > xnbd->disksize)
		err("exceed disksize");


	if (xnbd->readonly)
		buf = mmap(NULL, mapping_length, PROT_READ, MAP_SHARED,
				fd, mapping_start);
	else
		buf = mmap(NULL, mapping_length, PROT_READ | PROT_WRITE, MAP_SHARED,
				fd, mapping_start);
	if (buf == MAP_FAILED)
		err("disk mapping failed (iofrom %llu iolen %u), %m", iofrom, iolen);

	*mmaped_buf = buf;
	*mmaped_len = mapping_length;
	*mmaped_offset = mapping_start;

	char *iobuf = buf + (iofrom - mapping_start);

	return iobuf;
}


int poll_request_arrival(struct xnbd_session *ses)
{
	struct pollfd eventfds[2];

	for (;;) {
		eventfds[0].fd = ses->clientfd;
		eventfds[0].events = POLLRDNORM | POLLRDHUP;
		eventfds[1].fd = ses->event_listener_fd;
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


void check_disksize(char *diskpath, uint64_t disksize)
{
	int pgsize = getpagesize();

	if (disksize % 1024)
		warn("disksize is not a multiple of 1024 (nbd's default block size)");

	if (disksize % pgsize)
		warn("disksize is not a multiple of a page size (%d)", pgsize);

	/* A known issue is the end block of the disk; the size of which is not
	 * a multiple of CBLOCKSIZE. */
	if (disksize % CBLOCKSIZE)
		err("disksize is not a multiple of %d (xnbd's cache block size)",
				CBLOCKSIZE);

	/* off_t becomes 32bit singed integer when no large file support */
	info("disk %s size %llu B (%llu MB)", diskpath, disksize, disksize /1024 /1024);
}
