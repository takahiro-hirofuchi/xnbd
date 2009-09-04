/*
 * Copyright (C) 2008-2009 National Institute of Advanced Industrial Science and Technology
 *
 * Author: Takahiro Hirofuchi
 */
#include "bitmap.h"

/* ------------------------------------------------------------------------------------------ */

/*
 * TODO:
 *   - cleanup for 64bit
 *   - see bitmap code of Linux kernel
 **/

/* @size: total number of bits */
uint32_t *bitmap_setup(uint32_t size)
{
	uint32_t *bitmap_array;

	int nbitmap = size / 32 + ((size % 32) ? 1 : 0);

	bitmap_array = g_malloc0(sizeof(uint32_t) * nbitmap);

	dbg("allocate %u uint32_t bitmaps for %u bits", nbitmap, size);

	return bitmap_array;
}

uint32_t *bitmap_create(char *bitmapfile, uint32_t size, int *cbitmapfd, int *cbitmaplen)
{
	int fd;
	int nbitmap = size / 32 + ((size % 32) ? 1 : 0);
	void *buf = NULL;
	int buflen = sizeof(uint32_t) * nbitmap;
	int ret;


	fd = open(bitmapfile, O_RDWR | O_CREAT | O_NOATIME, S_IRUSR | S_IWUSR);
	if (fd < 0)
		err("open bitmapfile");

	{
		char *tmpbuf = g_malloc0(buflen);
		write_all(fd, tmpbuf, buflen);
		g_free(tmpbuf);
	}


	buf = mmap(NULL, buflen, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED)
		err("bitmap mapping failed");

	bzero(buf, buflen);

	/* get disk space for bitmap */
	ret = msync(buf, buflen, MS_SYNC);
	if (ret < 0)
		err("bitmap msync failed, %s", strerror(errno));

	info("bitmap %s (nbitmap %u nbits %u)", bitmapfile, nbitmap, size);

	*cbitmapfd = fd;
	*cbitmaplen = buflen;

	return (uint32_t *) buf;
}

#ifdef PSEUDOBITMAPALWAYSON
int bitmap_test(uint32_t *bitmap_array, uint32_t block_index)
{
	return 1;
}
#else
int bitmap_test(uint32_t *bitmap_array, uint32_t block_index)
{
	uint32_t val = 0;

	//printf("%p, %u\n",  bitmap_array, block_index);

	int bitmap_index = block_index / 32;
	uint32_t *bitmap = &(bitmap_array[bitmap_index]);

	val = *bitmap & (1 << (block_index % 32));

	//dbg("val %08x, bitmap %p block_index mod 32 %u, bitmap %08x", 
	//		val, bitmap, block_index % 32, *bitmap);

	if (val > 0)
		return 1;
	else
		return 0;
}
#endif

void bitmap_on(uint32_t *bitmap_array, uint32_t block_index)
{
	int bitmap_index = block_index / 32;
	uint32_t *bitmap = &(bitmap_array[bitmap_index]);

	//dbg("set_bitmap %08x", *bitmap);
	//printf("bitmap %p block_index mod 32 %d\n", bitmap, block_index % 32);

#ifndef PSEUDOBITMAP
	*bitmap |= (1 << (block_index % 32));
#endif

	//dbg("set_bitmap %08x", *bitmap);
}









