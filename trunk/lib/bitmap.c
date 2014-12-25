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

#include "bitmap.h"






/* some of the below definitions are from Linux kernel */
#define DIV_ROUND_UP(n,d)	(((n) + (d) - 1) / (d))
#define BITS_PER_BYTE           8
#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define BITS_PER_LONG		(sizeof(unsigned long) * BITS_PER_BYTE)

size_t bitmap_size(unsigned long nbits)
{
	unsigned long narrays = BITS_TO_LONGS(nbits);
	return sizeof(unsigned long) * narrays;
}

unsigned long *bitmap_alloc(unsigned long nbits)
{
	unsigned long *bitmap_array;
	unsigned long narrays = BITS_TO_LONGS(nbits);

	bitmap_array = g_new0(unsigned long, narrays);

	return bitmap_array;
}


void bitmap_sync_file(unsigned long *bitmap, size_t bitmaplen)
{
	dbg("msync bitmap %p", bitmap);
	int ret = msync(bitmap, bitmaplen, MS_SYNC);
	if (ret < 0)
		err("msync bitmap failed");
}


void bitmap_close_file(unsigned long *bitmap, size_t bitmaplen)
{
	/* do nothing if the size was zero when opened */
	if (!bitmap) {
		g_assert(bitmaplen == 0);
		return;
	}

	bitmap_sync_file(bitmap, bitmaplen);
	munmap_or_abort(bitmap, bitmaplen);
}


unsigned long *bitmap_open_file(const char *bitmapfile, unsigned long nbits, size_t *bitmaplen, int readonly, int zeroclear)
{
	void *buf = NULL;
	unsigned long narrays = BITS_TO_LONGS(nbits);
	size_t buflen = sizeof(unsigned long) * narrays;

	int mmap_flag = readonly ? PROT_READ : PROT_WRITE;
	int open_flag = readonly ? O_RDONLY : (O_RDWR | O_CREAT);

	/* mmap() of zero length results in EINVAL */
	if (nbits == 0) {
		warn("open a zero-length bitmap, %s", bitmapfile);
		return NULL;
	}

	{
		/* O_NOATIME will not give us visible performance improvement. Drop? */
		struct stat st;
		int ret = stat(bitmapfile, &st);
		if (ret < 0) {
			if (errno == ENOENT)
				open_flag |= O_NOATIME;
			else
				err("stat %s, %m", bitmapfile);
		} else {
			if (st.st_uid == geteuid())
				open_flag |= O_NOATIME;
		}
	}

	/* !zeroclear is considered "reuse_data" */

	/* if (readonly && !zeroclear)
	 *   open the existing file as readonly, and use data in it
	 *
	 * if (readonly && zeroclear)
	 *   error
	 *
	 * if (!readonly && !zeroclear)
	 *   open the existing file as read/write, and use data in it
	 *
	 * if (!readonly && zeroclear)
	 *   open the existing file as read/write, and zero-clear data
	 *
	 *
	 * if the obtained file size is different from the requested size,
	 *    (readonly && *) is not possible
	 *    (!readonly && !zeroclear) is not possible
	 *    (!readonly && zeroclear) is possible
	 *
	 * if the file is to be created,
	 *    (!readonly && *) is possible,
	 *       i.e., the given value of zeroclear is not referred
	 *
	 *
	 */

	{
		int fd = open(bitmapfile, open_flag, S_IRUSR | S_IWUSR);
		if (fd < 0)
			err("bitmap open %s, %m", bitmapfile);

		/* get the file size of a bitmap file */
		off_t size = get_disksize(fd);
		if (size != (off_t) buflen) {
			if (readonly)
				err("cannot resize readonly bitmap file (%s)", bitmapfile);

			/* if the bitmap file did not exist, the obtained size is zero */
			if (size == 0)
				zeroclear = 1;

			if (!zeroclear)
				err("deny using bitmap file (%s) without clearing it. The bitmap size is different (%ju != %zu)",
						bitmapfile, size, buflen);

			int ret = ftruncate(fd, buflen);
			if (ret < 0)
				err("ftruncate %m");
		}

		/* now we get the bitmap file of the required file size */

		buf = mmap(NULL, buflen, mmap_flag, MAP_SHARED, fd, 0);
		if (buf == MAP_FAILED)
			err("bitmap mapping failed");

		close(fd);
	}


	info("bitmap file %s (%zu bytes = %lu arrays of %zu bytes), %lu nbits",
			bitmapfile, buflen, narrays, sizeof(unsigned long), nbits);


	if (zeroclear) {
		g_assert(!readonly);

		info("make bitmap file (%s) zero-cleared", bitmapfile);
		memset(buf, 0, buflen);

		/* get disk space for bitmap */
		int ret = msync(buf, buflen, MS_SYNC);
		if (ret < 0)
			err("bitmap msync failed, %s", strerror(errno));
	} else
		info("reuse previous state from bitmap file %s", bitmapfile);


	*bitmaplen = buflen;

	return (unsigned long *) buf;
}

#if 0
unsigned long *bitmap_create(char *bitmapfile, unsigned long bits, int *cbitmapfd, size_t *cbitmaplen)
{
	int fd;
	int ret;
	void *buf = NULL;

	unsigned long narrays = BITS_TO_LONGS(bits);
	size_t buflen = sizeof(unsigned long) * narrays;


	fd = open(bitmapfile, O_RDWR | O_CREAT | O_NOATIME, S_IRUSR | S_IWUSR);
	if (fd < 0)
		err("open bitmapfile");

	{
		off_t ret = lseek(fd, (off_t) buflen-1, SEEK_SET);
		if (ret < 0)
			err("lseek");

		ret = write(fd, "\0", 1);
		if (ret < 0)
			err("write");
	}

	buf = mmap(NULL, buflen, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED)
		err("bitmap mapping failed");

	memset(buf, 0, buflen);

	/* get disk space for bitmap */
	ret = msync(buf, buflen, MS_SYNC);
	if (ret < 0)
		err("bitmap msync failed, %s", strerror(errno));

	info("bitmap %s, %lu arrays of %zu bytes, %lu nbits",
			bitmapfile, narrays, sizeof(unsigned long), bits);

	*cbitmapfd = fd;
	*cbitmaplen = buflen;

	return (unsigned long *) buf;
}
#endif


int bitmap_test(unsigned long *bitmap_array, unsigned long block_index)
{
	//printf("%p, %u\n",  bitmap_array, block_index);

	unsigned long bitmap_index = block_index / BITS_PER_LONG;
	unsigned long *bitmap = &(bitmap_array[bitmap_index]);

	unsigned long val = *bitmap & (1UL << (block_index % BITS_PER_LONG));

	//dbg("val %08x, bitmap %p block_index mod 32 %u, bitmap %08x",
	//		val, bitmap, block_index % 32, *bitmap);

	if (val > 0)
		return 1;
	else
		return 0;
}


void bitmap_on(unsigned long *bitmap_array, unsigned long block_index)
{
	unsigned long bitmap_index = block_index / BITS_PER_LONG;
	unsigned long *bitmap = &(bitmap_array[bitmap_index]);

	//dbg("set_bitmap %08x", *bitmap);
	//printf("bitmap %p block_index mod 32 %d\n", bitmap, block_index % 32);

	*bitmap |= (1UL << (block_index % BITS_PER_LONG));

	//dbg("set_bitmap %08x", *bitmap);
}


/* we can make it faster. use __builtin_popcountl()? */
unsigned long bitmap_popcount(unsigned long *bm, unsigned long nbits)
{
	unsigned long cached = 0;
	for (unsigned long index = 0; index < nbits; index++) {
		if (bitmap_test(bm, index))
			cached += 1;
	}

	return cached;
}
