/*
 * Copyright (C) 2008-2009 National Institute of Advanced Industrial Science and Technology
 *
 * Author: Takahiro Hirofuchi
 */
#include "bitmap.h"



#if 0
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
#endif



/* some of the below definitions are from Linux kernel */
#define DIV_ROUND_UP(n,d)	(((n) + (d) - 1) / (d))
#define BITS_PER_BYTE           8
#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define BITS_PER_LONG		(sizeof(unsigned long) * BITS_PER_BYTE)
unsigned long *bitmap_setup(unsigned long bits)
{
	unsigned long *bitmap_array;
	unsigned long narrays = BITS_TO_LONGS(bits);

	// bitmap_array = g_malloc0(sizeof(unsigned long) * narrays);
	bitmap_array = g_new0(unsigned long, narrays);

	return bitmap_array;
}


void bitmap_close_file(unsigned long *bitmap, size_t bitmaplen)
{
	dbg("msync bitmap %p", bitmap);
	int ret = msync(bitmap, bitmaplen, MS_SYNC);
	if (ret < 0) 
		err("msync bitmap failed");

	ret = munmap(bitmap, bitmaplen);
	if (ret < 0) 
		err("munmap bitmap failed");
}


unsigned long *bitmap_open_file(char *bitmapfile, unsigned long bits, size_t *bitmaplen, int readonly, int zeroclear)
{
	void *buf = NULL;
	unsigned long narrays = BITS_TO_LONGS(bits);
	size_t buflen = sizeof(unsigned long) * narrays;

	int mmap_flag = readonly ? PROT_READ : PROT_WRITE;
	int open_flag = readonly ? (O_RDONLY | O_NOATIME) : (O_RDWR | O_CREAT | O_NOATIME);

	{
		int fd = open(bitmapfile, open_flag, S_IRUSR | S_IWUSR);
		if (fd < 0)
			err("bitmap open, %s", bitmapfile);

		if (readonly) {
			uint64_t size = get_disksize(fd);
			if (size != buflen)
				err("bitmap size mismatch, %ju %zu", size, buflen);
		} else {
			int ret = ftruncate(fd, buflen);
			if (ret < 0)
				err("ftruncate %m");
		}

		buf = mmap(NULL, buflen, mmap_flag, MAP_SHARED, fd, 0);
		if (buf == MAP_FAILED)
			err("bitmap mapping failed");

		close(fd);
	}


	info("bitmap file %s (%zu bytes = %lu arrays of %zu bytes), %lu nbits",
			bitmapfile, buflen, narrays, sizeof(unsigned long), bits);
		
	if (!readonly) {
		if (zeroclear) {
			info("bitmap file %s zero-cleared", bitmapfile);
			bzero(buf, buflen);
		}

		/* get disk space for bitmap */
		int ret = msync(buf, buflen, MS_SYNC);
		if (ret < 0)
			err("bitmap msync failed, %s", strerror(errno));
	}


	*bitmaplen = buflen;

	return (unsigned long *) buf;
}

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

	bzero(buf, buflen);

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
