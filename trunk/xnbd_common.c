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

#include "xnbd.h"
#include "xnbd_common.h"


/*
 * CBLOCKSIZE must be a power of 2, because bit operations are used in
 * mmap_block_region functions. There is an assertion to check this in main()
 * of xnbd-server.
 *
 * 1024 or 8192, which is different from the page size, is also possible, but not well tested.
 **/
const unsigned int CBLOCKSIZE = 4096;

const int XNBD_PORT = 8520;





/* mmap a region of a given file. The start and the end of the region are also block-aligned.
 *
 * 1. Make sure the file size is a multiple of CBLOCKSIZE. Otherwise, ba_ioend
 * goes over the end of the file.
 * 2. CBLOCKSIZE must be a power of 2. Otherwise, bit operations for ba_iofrom and ba_ioend fail. */
struct mmap_block_region *mmap_block_region_create(int fd, off_t iofrom, size_t iolen, int readonly)
{
	/* block-aligned */
	off_t ba_iofrom = iofrom & ~(CBLOCKSIZE - 1);
	off_t ba_ioend  = ((iofrom + iolen) + (CBLOCKSIZE - 1)) & ~(CBLOCKSIZE - 1);

	struct mmap_region *mr = mmap_region_create(fd, ba_iofrom, (ba_ioend - ba_iofrom), readonly);

	struct mmap_block_region *mbr = g_slice_new(struct mmap_block_region);
	mbr->mr = mr;

	/* mr->iobuf points to ba_iofrom. */
	mbr->ba_iobuf = mr->iobuf;
	mbr->iobuf = (char *) mr->iobuf + (iofrom - ba_iofrom);

	mbr->ba_iofrom = ba_iofrom;

	return mbr;
}

void mmap_block_region_free(struct mmap_block_region *mbr)
{
	mmap_region_free(mbr->mr);
	g_slice_free(struct mmap_block_region, mbr);
}

#if 0
void *mmap_iorange(const off_t disksize, const bool readonly, const int fd, const off_t iofrom, const size_t iolen, char **mmaped_buf, size_t *mmaped_len, off_t *mmaped_offset)
{
	unsigned long index_start = get_bindex_sta(CBLOCKSIZE, iofrom);
	unsigned long index_end   = get_gindex_end(CBLOCKSIZE, iofrom + ioend);
	char *buf;

	//dbg("iofrom %llu iofrom + iolen %llu", iofrom, iofrom + iolen);
	//dbg("block_index_start %u end %u", index_start, index_end);

	/* (off_t) casting is essential !!! */
	off_t mapping_start  = (off_t) index_start * CBLOCKSIZE;
	size_t mapping_length = (index_end - index_start + 1) * CBLOCKSIZE;


	//dbg("mmapping_start %llu mapping_end %llu mapping_length %u",
	//		mapping_start, mapping_start + mapping_length,
	//		mapping_length);

	if ((mapping_start + (off_t) mapping_length) > disksize)
		err("exceed disksize");


	/*
	 * mapping_start (off_t) is 64bit in 64-bit environments or in the
	 * 32-bit envinronment with LARGEFILE. mapping_length (size_t) is 64 bit in
	 * 64-bit environments, 32 bit in 32-bit environments.
	 **/

	if (readonly)
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
#endif


int poll_request_arrival(struct xnbd_session *ses)
{
	return wait_until_readable(ses->clientfd, ses->pipe_worker_fd);
}

/* --proxy and --cow-target will depend on mmap_block_region */
void check_disksize(off_t disksize)
{
	/* This restriction makes it simple to handle the end of the disk file. */
	if (disksize % CBLOCKSIZE)
		err("disksize %jd must be a multiple of CBLOCKSIZE(%d)", disksize, CBLOCKSIZE);
}

unsigned long get_disk_nblocks(off_t disksize)
{
	off_t nblocks64 = disksize / CBLOCKSIZE + ((disksize % CBLOCKSIZE) ? 1U : 0U);

	/*
	 * xnbd->nblocks is unsigned long. In 32-bit arch, the maximum size is
	 * 16TBytes.
	 **/
	if (sizeof(unsigned long) == sizeof(uint32_t))
		g_assert(nblocks64 <= UINT32_MAX);

	return (unsigned long) nblocks64;
}

int get_log_fd(const char *path)
{
        int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
        if (fd < 0)
                err("open %s, %m", path);

        return fd;
}
