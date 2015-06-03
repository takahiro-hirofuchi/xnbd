/*
 * xNBD - an enhanced Network Block Device program
 *
 * Copyright (C) 2008-2014 National Institute of Advanced Industrial Science
 * and Technology
 *
 * Author: Takahiro Hirofuchi <t.hirofuchi+xnbd _at_ aist.go.jp>
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


const int XNBD_PORT = 8520;





/* mmap a region of a given file. The start and the end of the region are block-aligned. */
struct mmap_block_region *mmap_block_region_create(int fd, off_t disksize, off_t iofrom, size_t iolen, int readonly)
{
	/* cast to off_t in order to avoid overflow */
	const off_t blocksize = CBLOCKSIZE;
	/* block-aligned */
	off_t ba_iofrom = iofrom & ~(blocksize - 1);
	off_t ba_ioend  = ((iofrom + iolen) + (blocksize - 1)) & ~(blocksize - 1);

	/* This may happen when the disk size is not a multiple of CBLOCKSIZE */
	if (ba_ioend > disksize) {
		info("The disk end offset is not block-aligned. (disksize %ju ba_ioend %ju)", disksize, ba_ioend);
		ba_ioend = disksize;
	}

	struct mmap_region *mr = mmap_region_create(fd, ba_iofrom, (ba_ioend - ba_iofrom), readonly);

	struct mmap_block_region *mbr = g_slice_new(struct mmap_block_region);
	mbr->mr = mr;

	dbg("ba_iofrom %ju [iofrom %ju ioend %ju] ba_ioend %ju",
			ba_iofrom, iofrom, iofrom  + iolen, ba_ioend);

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


int poll_request_arrival(struct xnbd_session *ses)
{
	return wait_until_readable(ses->clientfd, ses->pipe_worker_fd);
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
