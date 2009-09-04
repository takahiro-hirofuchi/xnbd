/* 
 * Copyright (C) 2008-2009 National Institute of Advanced Industrial Science and Technology
 */
#include "xnbd.h"



/* must be a multiple of PAGESIZE for mmap. */
/* A PAGESIZE is plused to include a header */
#define logsize PAGESIZE


struct cachestat {
	uint32_t nblocks;

	uint32_t cache_odread;
	uint32_t cache_odwrite;
	uint32_t cache_bgcopy;

	uint32_t io_blocks;
	uint32_t read_blocks;
	uint32_t written_blocks;

	uint32_t cache_hit;
	uint32_t cache_miss;
};

void cachestat_dump(char *path)
{
	int fd;
	char *buf;
	int ret;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		err("open cachestat file %s, %s", path, strerror(errno));

	buf = mmap(NULL, logsize, PROT_READ, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED)
		err("disk mapping failed, %s", strerror(errno));
	
	struct cachestat *st = (struct cachestat *) buf;

	printf("nblocks %u\n", st->nblocks);
	printf("cached_by_ondemand_read %u\n", st->cache_odread);
	printf("cached_by_ondemand_write %u\n", st->cache_odwrite);
	printf("cached_by_bgcopy %u\n", st->cache_bgcopy);

	printf("io_blocks %u\n", st->io_blocks);
	printf("read_blocks %u\n", st->read_blocks);
	printf("written_blocks  %u\n", st->written_blocks);

	printf("cache_hit %u\n", st->cache_hit);
	printf("cache_miss %u\n", st->cache_miss);

	printf("cache_hit_ratio %f\n", 100.0 * st->cache_hit / (st->cache_hit + st->cache_miss));
	printf("transferred blocks %u\n", st->cache_miss + st->cache_bgcopy);

	ret = munmap(buf, logsize);
	if (ret < 0) 
		warn("munmap failed");

	close(fd);
}


void cachestat_dump_loop(char *path, int interval)
{
	int fd;
	char *buf;
	int ret;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		err("open cachestat file %s, %s", path, strerror(errno));

	buf = mmap(NULL, logsize, PROT_READ, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED)
		err("disk mapping failed, %s", strerror(errno));
	
	struct cachestat *st = (struct cachestat *) buf;

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


	uint32_t io_blocks_prev = 0;
	uint32_t cache_hit_prev = 0;
	uint32_t cache_miss_prev = 0;
	uint32_t transferred_blocks_prev = 0;

	for (;;) {
		time_t now = time(NULL);

		printf("%lu ", now);
		printf("%u ", st->nblocks);
		printf("%u ", st->cache_odread);
		printf("%u ", st->cache_odwrite);
		printf("%u ", st->cache_bgcopy);
		printf("%f  ", (st->cache_odread + st->cache_odwrite + st->cache_bgcopy) * 100.0 / st->nblocks);

		/* on-demand I/O */
		printf("%u ", st->io_blocks);
		printf("%u ", st->read_blocks);
		printf("%u ", st->written_blocks);
		printf("%f  ", 1.0 * (st->io_blocks - io_blocks_prev) / interval);


		printf("%u ", st->cache_hit);
		printf("%u ", st->cache_miss);
		uint32_t cache_hit_diff = st->cache_hit - cache_hit_prev;
		uint32_t cache_miss_diff = st->cache_miss - cache_miss_prev;
		printf("%f ", 100.0 * cache_hit_diff / (cache_hit_diff + cache_miss_diff));
		printf("%f  ", 100.0 * st->cache_hit / (st->cache_hit + st->cache_miss));

		uint32_t transferred_blocks = st->cache_miss + st->cache_bgcopy;
		float transferred_blocks_per_sec  = 1.0 * (transferred_blocks - transferred_blocks_prev) / interval;
		printf("%u ", transferred_blocks);
		printf("%f\n", transferred_blocks_per_sec);

		io_blocks_prev = st->io_blocks;
		cache_hit_prev = st->cache_hit;
		cache_miss_prev = st->cache_miss;
		transferred_blocks_prev = transferred_blocks;
		

		fflush(stdout);
		sleep(interval);
	}

	ret = munmap(buf, logsize);
	if (ret < 0) 
		warn("munmap failed");

	close(fd);
}


#ifdef CACHESTAT_ENABLED
static struct cachestat *cachest;
static int cachestfd;
static int cachest_initialized = 0;
static char *cachestbuf;

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

int cachestat_initialize(char *path, uint32_t nblocks)
{
	cachestfd = open(path, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
	if (cachestfd < 0) {
		err("open cachestfd  %s, %s", path, strerror(errno));
	}

	{
		char *tmpbuf = g_malloc(logsize);
		bzero(tmpbuf, logsize);
		writeit(cachestfd, tmpbuf, logsize);
		g_free(tmpbuf);
	}

	
	info("cachest file %s size %llu B\n", path, (off64_t) logsize);

	cachestbuf = mmap(NULL, logsize, PROT_READ | PROT_WRITE, MAP_SHARED, cachestfd, 0);
	if (cachestbuf == MAP_FAILED)
		err("disk mapping failed, %s", strerror(errno));

	cachest = (struct cachestat *) cachestbuf;
	cachest->nblocks = nblocks;

	cachest_initialized = 1;

	return 0;
}

int cachestat_shutdown(void)
{
	int ret;

	if (!cachest_initialized)
		return 0;

	ret = msync(cachestbuf, logsize, MS_SYNC);
	if (ret < 0) 
		warn("msync failed");

	ret = munmap(cachestbuf, logsize);
	if (ret < 0) 
		warn("munmap failed");

	close(cachestfd);

	return 0;
}

#else
inline void cachestat_cache_odread(void) { return; }
inline void cachestat_cache_odwrite(void) { return; }
inline void cachestat_cache_bgcopy(void) { return; }
inline void cachestat_read_block(void) { return; }
inline void cachestat_write_block(void) { return; }
inline void cachestat_miss(void) { return; }
inline void cachestat_hit(void) { return; }
int cachestat_initialize(char *path __attribute__((unused)), uint32_t nblocks __attribute__((unused))) { return 0; }
int cachestat_shutdown(void) { return 0; }

#endif
