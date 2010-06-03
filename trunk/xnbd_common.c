/* 
 * Copyright (C) 2008-2010 National Institute of Advanced Industrial Science and Technology
 */
#include "xnbd.h"

const unsigned int CBLOCKSIZE = 4096;
unsigned int PAGESIZE = 4096;





/* target file size must be a multiple of PAGESIZE, for the last block handling */

struct mmap_partial *mmap_partial_map(int fd, off_t iofrom, const size_t iolen_in, int readonly)
{
	const ssize_t iolen = (const ssize_t) iolen_in;  /* avoid warnings in x86_64 */
	size_t mmap_length;

	off_t iofrom_fraction = iofrom % PAGESIZE;
	off_t mmap_offset = iofrom - iofrom_fraction;


	off_t ioend_fraction = (iofrom + iolen) % PAGESIZE;
	if (ioend_fraction)
		mmap_length = (size_t) ((iofrom + iolen) - ioend_fraction + PAGESIZE - mmap_offset);
	else
		mmap_length = (size_t) ((iofrom + iolen) - mmap_offset);

	//off_t index_end   = DIV_ROUND_UP(iofrom + iolen, PAGESIZE);

	{
		unsigned long inds, inde;
		calc_block_index(PAGESIZE, iofrom, iolen_in, &inds, &inde);
		if ((off_t) inds * PAGESIZE != mmap_offset)
			err("check failed 0: %ju, %ju", (off_t) inds * PAGESIZE, mmap_offset);

		size_t mmap_len2 = (inde - inds + 1) * (unsigned) PAGESIZE;

		if (mmap_len2 != mmap_length)
			err("check failed 1: %zu, %zu", mmap_len2, mmap_length);
	}


	char *buf = NULL;

	if (readonly)
		buf = mmap(NULL, mmap_length, PROT_READ, MAP_SHARED, fd, mmap_offset);
	else
		buf = mmap(NULL, mmap_length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, mmap_offset);
	if (buf == MAP_FAILED)
		err("disk mapping failed (iofrom %ju iolen %zu), %m", iofrom, iolen);


	struct mmap_partial *mpinfo = g_malloc(sizeof(struct mmap_partial));

	mpinfo->buf = buf;
	mpinfo->len = mmap_length;
	mpinfo->offset = mmap_offset;

	mpinfo->iobuf = buf + iofrom_fraction;

	return mpinfo;
}

void mmap_partial_unmap(struct mmap_partial *mpinfo)
{
	int ret = munmap(mpinfo->buf, mpinfo->len);
	if (ret < 0) 
		warn("munmap failed, %m");

	g_free(mpinfo);
}



void get_io_range_index(off_t iofrom, size_t iolen, unsigned long *index_start, unsigned long *index_end)
{
	calc_block_index(CBLOCKSIZE, iofrom, iolen, index_start, index_end);
}





void *mmap_iorange(struct xnbd_info *xnbd, int fd, off_t iofrom, size_t iolen, char **mmaped_buf, size_t *mmaped_len, off_t *mmaped_offset)
{
	unsigned long index_start, index_end;
	char *buf;

	get_io_range_index(iofrom, iolen, &index_start, &index_end);

	//dbg("iofrom %llu iofrom + iolen %llu", iofrom, iofrom + iolen);
	//dbg("block_index_start %u end %u", index_start, index_end);

	/* (uint64_t) casting is essential !!! */
	off_t mapping_start  = (off_t) index_start * CBLOCKSIZE;
	size_t mapping_length = (index_end - index_start + 1) * CBLOCKSIZE;


	//dbg("mmapping_start %llu mapping_end %llu mapping_length %u", 
	//		mapping_start, mapping_start + mapping_length,
	//		mapping_length);

	if ((mapping_start + (off_t) mapping_length) > xnbd->disksize)
		err("exceed disksize");


	/*
	 * mapping_start (off_t) is 64bit in 64-bit environments or in the
	 * 32-bit envinronment with LARGEFILE. mapping_length (size_t) is 64 bit in
	 * 64-bit envinronments, 32 bit in 32-bit envinronments.
	 **/

	if (xnbd->readonly)
		buf = mmap(NULL, mapping_length, PROT_READ, MAP_SHARED,
				fd, mapping_start);
	else
		buf = mmap(NULL, mapping_length, PROT_READ | PROT_WRITE, MAP_SHARED,
				fd, mapping_start);
	if (buf == MAP_FAILED)
		err("disk mapping failed (iofrom %ju iolen %zu), %m", iofrom, iolen);

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


void check_disksize(char *diskpath, off_t disksize)
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
	info("disk %s size %ju B (%ju MB)", diskpath, disksize, disksize /1024 /1024);
}

unsigned long get_disk_nblocks(off_t disksize)
{
	if (disksize % CBLOCKSIZE)
		warn("disksize is not a multiple of CBLOCKSIZE");

	/* setup bitmap */
	off_t nblocks64 = disksize / CBLOCKSIZE + ((disksize % CBLOCKSIZE) ? 1U : 0U);

	/*
	 * xnbd->nblocks is unsigned long. In 32-bit arch, the maximum size is
	 * 16TBytes.
	 **/
	if (sizeof(unsigned long) == sizeof(uint32_t))
		g_assert(nblocks64 <= UINT32_MAX);

	return (unsigned long) nblocks64;
}

