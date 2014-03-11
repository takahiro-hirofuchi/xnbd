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



struct cachestat {
	unsigned long nblocks;

	unsigned long cache_odread;
	unsigned long cache_odwrite;
	unsigned long cache_bgcopy;

	unsigned long io_blocks;
	unsigned long read_blocks;
	unsigned long written_blocks;

	unsigned long cache_hit;
	unsigned long cache_miss;
};

void cachestat_dump(char *path)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		err("open cachestat file %s, %s", path, strerror(errno));

	struct cachestat *st = mmap_or_abort(NULL, sizeof(struct cachestat), PROT_READ, MAP_SHARED, fd, 0);
	close(fd);


	printf("nblocks %lu\n", st->nblocks);
	printf("cached_by_ondemand_read %lu\n", st->cache_odread);
	printf("cached_by_ondemand_write %lu\n", st->cache_odwrite);
	printf("cached_by_bgcopy %lu\n", st->cache_bgcopy);

	printf("io_blocks %lu\n", st->io_blocks);
	printf("read_blocks %lu\n", st->read_blocks);
	printf("written_blocks  %lu\n", st->written_blocks);

	printf("cache_hit %lu\n", st->cache_hit);
	printf("cache_miss %lu\n", st->cache_miss);

	printf("cache_hit_ratio %lf\n", 100.0 * (double) st->cache_hit / (double) (st->cache_hit + st->cache_miss));
	printf("transferred blocks %lu\n", st->cache_miss + st->cache_bgcopy);

	munmap_or_abort(st, sizeof(struct cachestat));
}


void cachestat_dump_loop(char *path, unsigned int interval)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		err("open cachestat file %s, %s", path, strerror(errno));

	struct cachestat *st = mmap_or_abort(NULL, sizeof(struct cachestat), PROT_READ, MAP_SHARED, fd, 0);
	close(fd);

	printf("#time nblocks ");
	printf("cached_by_ondemand_read ");
	printf("cached_by_ondemand_write ");
	printf("cached_by_bgcopy ");
	printf("cached_ratio  ");

	printf("io_blocks ");
	printf("read_blocks ");
	printf("written_blocks  ");
	printf("io_blocks_per_sec  ");

	printf("cache_hit ");
	printf("cache_miss ");
	printf("cache_hit_ratio ");
	printf("cache_hit_ratio_total  ");

	printf("transferred_blocks ");
	printf("transferred_blocks_per_sec\n");


	unsigned long io_blocks_prev = 0;
	unsigned long cache_hit_prev = 0;
	unsigned long cache_miss_prev = 0;
	unsigned long transferred_blocks_prev = 0;

	for (;;) {
		time_t now = time(NULL);

		printf("%lu ", now);
		printf("%lu ", st->nblocks);
		printf("%lu ", st->cache_odread);
		printf("%lu ", st->cache_odwrite);
		printf("%lu ", st->cache_bgcopy);
		printf("%lf  ", (double) (st->cache_odread + st->cache_odwrite + st->cache_bgcopy) * 100.0 / (double) st->nblocks);

		/* on-demand I/O */
		printf("%lu ", st->io_blocks);
		printf("%lu ", st->read_blocks);
		printf("%lu ", st->written_blocks);
		printf("%lf  ", 1.0 * (double) (st->io_blocks - io_blocks_prev) / (double) interval);


		printf("%lu ", st->cache_hit);
		printf("%lu ", st->cache_miss);
		unsigned long cache_hit_diff = st->cache_hit - cache_hit_prev;
		unsigned long cache_miss_diff = st->cache_miss - cache_miss_prev;
		printf("%lf ", 100.0 * (double) cache_hit_diff / (double) (cache_hit_diff + cache_miss_diff));
		printf("%lf  ", 100.0 * (double) st->cache_hit / (double) (st->cache_hit + st->cache_miss));

		unsigned long transferred_blocks = st->cache_miss + st->cache_bgcopy;
		double transferred_blocks_per_sec  = 1.0 * (double) (transferred_blocks - transferred_blocks_prev) / interval;
		printf("%lu ", transferred_blocks);
		printf("%lf\n", transferred_blocks_per_sec);

		io_blocks_prev = st->io_blocks;
		cache_hit_prev = st->cache_hit;
		cache_miss_prev = st->cache_miss;
		transferred_blocks_prev = transferred_blocks;


		fflush(stdout);
		sleep(interval);
	}

	munmap_or_abort(st, sizeof(struct cachestat));
}


#ifdef CACHESTAT_ENABLED
static struct cachestat *cachest = NULL;

inline void cachestat_cache_odread(void)
{
	cachest->cache_odread += 1;
}

inline void cachestat_cache_odwrite(void)
{
	cachest->cache_odwrite += 1;
}

inline void cachestat_cache_bgcopy(void)
{
	cachest->cache_bgcopy += 1;
}

inline void cachestat_read_block(void)
{
	cachest->io_blocks += 1;
	cachest->read_blocks += 1;
}

inline void cachestat_write_block(void)
{
	cachest->io_blocks += 1;
	cachest->written_blocks += 1;
}

inline void cachestat_hit(void)
{
	cachest->cache_hit += 1;
}

inline void cachestat_miss(void)
{
	cachest->cache_miss += 1;
}

void cachestat_initialize(const char *path, unsigned long nblocks)
{
	int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		err("open cachestfd  %s, %s", path, strerror(errno));
	}

	info("cachest file %s (%zu bytes)\n", path, sizeof(struct cachestat));

	cachest = mmap_or_abort(NULL, sizeof(struct cachestat), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	cachest->nblocks = nblocks;

	close(fd);
}

void cachestat_shutdown(void)
{
	g_assert(cachest);

	int ret = msync(cachest, sizeof(struct cachestat), MS_SYNC);
	if (ret < 0)
		warn("msync failed");

	munmap_or_abort(cachest, sizeof(struct cachestat));
}

#else
inline void cachestat_cache_odread(void) { return; }
inline void cachestat_cache_odwrite(void) { return; }
inline void cachestat_cache_bgcopy(void) { return; }
inline void cachestat_read_block(void) { return; }
inline void cachestat_write_block(void) { return; }
inline void cachestat_miss(void) { return; }
inline void cachestat_hit(void) { return; }
void cachestat_initialize(const char *path __attribute__((unused)), unsigned long nblocks __attribute__((unused))) { return; }
void cachestat_shutdown(void) { return; }
#endif
