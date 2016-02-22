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

//#define DEBUG_COW 1


#ifdef DEBUG_COW
const char *check_write_path = "/tmp/check_write";
static int has_lock = 0;
static const int do_check_write = 0;

#include <sys/file.h>

void check_write(void)
{
	if (!do_check_write)
		return;

	/* Before execution, do echo 0 > check_write_path . */
	int fd = open(check_write_path, O_RDWR, 0600);
	if (fd < 0)
		err("open %s %m", check_write_path);

	int ret = flock(fd, LOCK_EX);
	if (ret < 0)
		err("flock LOCK_EX");

	char buf[100];

	ret = read(fd, buf, sizeof(buf));
	if (ret < 0)
		err("read");

	int prev_pid = atoi(buf);
	int my_pid   = getpid();

	if (!has_lock) {
		info("write lock moved: %d -> %d", prev_pid, my_pid);

		ret = ftruncate(fd, 0);
		if (ret < 0)
			err("ftruncate, %m");

		sprintf(buf, "%d", my_pid);

		ret = pwrite(fd, buf, strlen(buf), 0);
		if (ret < 0)
			err("write");

		has_lock = 1;

	} else {
		/* check the prev write was performed by me */
		if (prev_pid != my_pid) {
			warn("*** WRONG ORDERING OF WRITE REQUEST ***, prev_pid %d my_pid %d", prev_pid, my_pid);
		}
	}

	ret = flock(fd, LOCK_UN);
	if (ret < 0)
		err("flock LOCK_UN");

	close(fd);
}

char *debug_buf = NULL;

void setup_debug_buf(struct disk_stack *ds)
{
	char *path = ds->image[0]->path;
	off_t len = ds->disksize;

	int fd = open(path, O_RDONLY, 0600);
	if (fd < 0)
		err("open, %m");

	mmap_or_abort(NULL, len, PROT_READ, MAP_SHARED, fd, 0);

	close(fd);

	debug_buf = g_malloc0(len);

	memcpy(debug_buf, buf, len);

	munmap_or_abort(buf, len);

	info("setup debug_buf done");
}

void compare_iov_and_buf(struct iovec *iov, int iov_size, char *buf, int buflen)
{
	int offset = 0;

	for (int i = 0; i < iov_size; i++) {
		int ret = memcmp(iov[i].iov_base, buf + offset, iov[i].iov_len);
		if (ret) {
			warn("*** buf mismatch ***");

			int found = 0;
			for (unsigned int j = 0; j < iov[i].iov_len; j++) {
				char *ch0 = iov[i].iov_base + j;
				char *ch1 = buf + offset + j;

				if (*ch0 != *ch1) {
					info("mismatch at %u bytes", j);
					found = 1;
					break;
				}
			}

			if (!found)
				err("not found?");

			info("### iov[%d].iov_base %p", i, iov[i].iov_base);
			dump_buffer_all(iov[i].iov_base, iov[i].iov_len);
			info("### buf + offset %p", buf + offset);
			dump_buffer_all(buf + offset, iov[i].iov_len);
			err("mismatch");
		}

		offset += iov[i].iov_len;
	}

	if (offset != buflen)
		err("mismatch");
}

void copy_buf_to_iov(struct iovec *iov, int iov_size, char *buf, size_t buflen)
{
	size_t offset = 0;

	for (int i = 0; i < iov_size; i++) {
		memcpy(iov[i].iov_base, buf + offset, iov[i].iov_len);

		offset += iov[i].iov_len;
	}

	if (offset != buflen)
		err("mismatch");
}
#endif


/* 0xff filled, readonly, munmap possible */
static void *get_filled_readonly_buffer(char *template, size_t buflen)
{
	g_assert(buflen);

	int fd = mkstemp(template);
	if (fd < 0)
		err("mkstemp %m");

	int ret = ftruncate(fd, buflen);
	if (ret < 0)
		err("ftruncate %m");

	char *buf = mmap_or_abort(NULL, buflen, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	memset(buf, 0xff, buflen);
	munmap_or_abort(buf, buflen);

	/* map it again as readonly */
	buf = mmap_or_abort(NULL, buflen, PROT_READ, MAP_SHARED, fd, 0);

	close(fd);
	unlink(template);

	return buf;
}

struct disk_stack *create_disk_stack(char *diskpath)
{
	int diskfd;
	off_t disksize;

	diskfd = open(diskpath, O_RDONLY);
	if (diskfd < 0) {
		if (errno == EOVERFLOW)
			warn("enable large file support!");
		err("open, %s", strerror(errno));
	}

	disksize = get_disksize(diskfd);
	if (disksize == 0)
		err("the size of %s is zero", diskpath);

	/* off_t is 32bit singed integer without the large file support */
	info("disk %s size %ju B (%ju MB)", diskpath, disksize, disksize /1024 /1024);

	struct disk_stack *ds = g_malloc0(sizeof(struct disk_stack));
	ds->nlayers = 0;
	ds->disksize = disksize;

	struct disk_image *di = g_malloc0(sizeof(struct disk_image));
	di->diskfd = diskfd;
	di->path = g_strdup(diskpath);

	unsigned long nblocks = get_disk_nblocks(ds->disksize);


	/* the bitmap of the layer zero is filled with 0xff */
	di->bmpath = g_strdup_printf("/dev/shm/xnbd.XXXXXX");
	di->bmlen = bitmap_size(nblocks);
	di->bm = get_filled_readonly_buffer(di->bmpath, di->bmlen);

	di->persistent = true;

	ds->image[0] = di;

	info("add disk_stack[%d] %s %s (%s)", ds->nlayers, di->path, di->bmpath,
			di->persistent ? "persistent" : "volatile");

	ds->nlayers += 1;

	return ds;
}



void destroy_disk_stack(struct disk_stack *ds)
{
	for (int i = 0; i < ds->nlayers; i++) {
		struct disk_image *di = ds->image[i];
		close(di->diskfd);

		int ret = msync(di->bm, di->bmlen, MS_SYNC);
		if (ret < 0)
			err("msync");
		munmap_or_abort(di->bm, di->bmlen);

		if (!di->persistent) {
			/* never delete the base image */
			g_assert(i != 0);

			int ret = unlink(di->path);
			if (ret < 0)
				err("unlink %m");

			ret = unlink(di->bmpath);
			if (ret < 0)
				err("unlink %m");

			info("unlink %s (%s)", di->path, di->bmpath);
		}

		g_free(di->path);
		g_free(di->bmpath);

		g_free(di);
	}

	g_free(ds);
}

void disk_stack_add_layer(struct disk_stack *ds, char *diskpath, int diskfd, char *bmpath, unsigned long *bm, size_t bmlen, bool persistent)
{
	if (ds->nlayers == MAX_DISKIMAGESTACK)
		err("no space");

	off_t disksize = get_disksize(diskfd);
	g_assert(ds->disksize == disksize);

	struct disk_image *di = g_malloc0(sizeof(struct disk_image));
	di->diskfd = diskfd;
	di->path   = g_strdup(diskpath);

	di->bmpath = g_strdup(bmpath);
	di->bm     = bm;
	di->bmlen  = bmlen;

	di->persistent = persistent;

	info("add disk_stack[%d] %s %s (%s)", ds->nlayers, di->path, di->bmpath,
			di->persistent ? "persistent" : "volatile");
	ds->image[ds->nlayers] = di;
	ds->nlayers += 1;
}




static void copy_block_to_top_layer(struct disk_stack *ds, struct disk_stack_io *io, unsigned long index, unsigned long start_index, off_t disksize)
{
	bool found = false;

	size_t iolen = confine_iolen_within_disk(disksize, (off_t) index * CBLOCKSIZE, CBLOCKSIZE);

	for (int i = ds->nlayers - 1; i >= 0; i--) {
		struct disk_image *di = ds->image[i];

		if (bitmap_test(di->bm, index)) {
			dbg("index %lu found at layer %d", index, i);

			char *dstptr = (char *) io->mbrs[ds->nlayers - 1]->ba_iobuf + (index - start_index) * CBLOCKSIZE;
			char *srcptr = (char *) io->mbrs[i]->ba_iobuf + (index - start_index) * CBLOCKSIZE;

			memcpy(dstptr, srcptr, iolen);

			found = true;
			break;
		}
	}

	if (!found)
		err("bug");
}

static void dump_disk_stack(struct disk_stack *ds)
{
	info("disk stack (base %s, size %ju)", ds->image[0]->path, ds->disksize);
	for (int i = 0; i < ds->nlayers; i++) {
		info("  layer %d: %s %s %s", i, ds->image[i]->path, ds->image[i]->bmpath,
				ds->image[i]->persistent ? "persistent" : "volatile");
	}
}


/*
 * Find all the layers of the disk image and register them as readonly.
 * For example, it stacks found layers as follows:
 *    /VM/disk.img.cow0.layerN		(bitmap /VM/disk.img.cow0.layerN.bm)
 *    ...
 *    /VM/disk.img.cow0.layer2		(bitmap /VM/disk.img.cow0.layer2.bm)
 *    /VM/disk.img.cow0.layer1		(bitmap /VM/disk.img.cow0.layer1.bm)
 *    /VM/disk.img
 *
 * TODO: somebody may want to open the top layer for read/write?
 */
struct disk_stack *xnbd_cow_target_open_disk_stack_readonly(char *diskpath, int cowid)
{
	struct disk_stack *ds = create_disk_stack(diskpath);
	int layer = 1;

	for (;;) {
		char *cowpath = g_strdup_printf("%s.cow%d.layer%d", diskpath, cowid, layer);
		int cowfd = open(cowpath, O_RDONLY);
		if (cowfd < 0) {
			if (errno == ENOENT)
				break;
			else
				err("open %s, %m", cowpath);
		}

		off_t disksize = get_disksize(cowfd);
		if (disksize != ds->disksize)
			err("%s (%ju bytes) mismatches the disk stack (%ju)",
					diskpath, disksize, ds->disksize);

		char *bmpath = g_strdup_printf("%s.cow%d.layer%d.bm", diskpath, cowid, layer);
		size_t bmlen;
		/* readonly, keep data */
		unsigned long *bm = bitmap_open_file(bmpath, get_disk_nblocks(ds->disksize), &bmlen, 1, 0);

		disk_stack_add_layer(ds, cowpath, cowfd, bmpath, bm, bmlen, true);

		g_free(cowpath);
		g_free(bmpath);

		layer += 1;
	}

	if (ds->nlayers == 1)
		err("no layers found for cow%d of %s", cowid, diskpath);

	dump_disk_stack(ds);

	return ds;
}


/*
 * Open the base image as readonly and put a new read/write layer on it.
 *
 * Note:
 *   Written data is not persistent. The added layer is gone upon shutdown.
 *
 *   Snapshoting (i.e, adding a new layer furthermore) is not yet implemented.
 *
 *   xnbd-server automatically finds an unused cowid for the base image, and
 *   creates a new cow image with it. This allows users to invoke multiple
 *   xnbd-servers using the base image, each of which saves written data
 *   indivisually.
 *
 *   If we enable xnbd-server to keep written data persistent, we should be
 *   able to give xnbd-server cowid in the command line.
 *
 * */
struct disk_stack *xnbd_cow_target_create_disk_stack(char *diskpath)
{
	struct disk_stack *ds = create_disk_stack(diskpath);
	int cowid = 0;

	/* get a unique cowpath */
	char *cowpath = NULL;;
	int cowfd;
	for (;;) {
		cowpath = g_strdup_printf("%s.cow%d.layer%d", diskpath, cowid, 1);

		cowfd = open(cowpath, O_RDWR | O_CREAT | O_EXCL, 0600);
		if (cowfd < 0) {
			if (errno == EEXIST) {
				cowid += 1;
				g_free(cowpath);
				close(cowfd);
				continue;
			} else
				err("open %m");
		}

		break;
	}

	int ret = ftruncate(cowfd, ds->disksize);
	if (ret < 0)
		err("ftruncate %m");

	char *bmpath = g_strdup_printf("%s.cow%d.layer%d.bm", diskpath, cowid, 1);
	size_t bmlen;
	/* read/write zero-clear */
	unsigned long *bm = bitmap_open_file(bmpath, get_disk_nblocks(ds->disksize), &bmlen, 0, 1);

	disk_stack_add_layer(ds, cowpath, cowfd, bmpath, bm, bmlen, false);

	g_free(cowpath);
	g_free(bmpath);

	dump_disk_stack(ds);

	return ds;
}

/* currently, cow-target is not persistent */
void xnbd_cow_target_close_disk_stack(struct disk_stack *ds)
{
	info("cow disk close (base image %s)", ds->image[0]->path);
	g_assert(ds);

	destroy_disk_stack(ds);
}



static struct disk_stack_io *create_disk_stack_io(struct disk_stack *ds)
{
	struct disk_stack_io *io = g_malloc0(sizeof(struct disk_stack_io));
	io->ds = ds;

	return io;
}

struct disk_stack_io *disk_stack_mmap(struct disk_stack *ds, off_t iofrom, size_t iolen, int reading)
{
	off_t ioend = iofrom + iolen;
	unsigned long index_sta = get_bindex_sta(CBLOCKSIZE, iofrom);
	unsigned long index_end = get_bindex_end(CBLOCKSIZE, ioend);

	dbg("iofrom %ju ioend %ju", iofrom, ioend);
	dbg("index_sta %lu end %lu", index_sta, index_end);


	struct disk_stack_io *io = create_disk_stack_io(ds);

	/* mmap() all layers */
	for (int i = 0; i < ds->nlayers; i++) {
		struct disk_image *di = ds->image[i];

		int readonly = 1;
		if (!di->persistent)
			readonly = 0;

		io->mbrs[i] = mmap_block_region_create(di->diskfd, ds->disksize, iofrom, iolen, readonly);
	}


	struct iovec *iov = NULL;
	unsigned int iov_size = 0;

	if (reading) {
		/* the number of iovec in readv()'s args is int */
		g_assert((index_end - index_sta + 1) <= UINT32_MAX);

		iov_size = (unsigned int) (index_end - index_sta + 1);
		iov = g_new0(struct iovec, iov_size);

		for (unsigned long index = index_sta; index <= index_end; index++) {
			bool found = true;

			for (int i = ds->nlayers - 1; i >= 0; i--) {
				struct disk_image *di = ds->image[i];

				if (bitmap_test(di->bm, index)) {
					dbg("index %lu found at layer %d", index, i);

					char *ba_iobuf = io->mbrs[i]->ba_iobuf;
					char *iobuf = io->mbrs[i]->iobuf;

					off_t chunk_iofrom = MAX(iofrom, (off_t) index * CBLOCKSIZE);
					off_t chunk_ioend  = MIN(ioend, (off_t) (index + 1) * CBLOCKSIZE);
					size_t chunk_iolen = (size_t) chunk_ioend - chunk_iofrom;
					char *chunk_iobuf  = MAX(iobuf, (ba_iobuf + (index - index_sta) * CBLOCKSIZE));

					g_assert(chunk_iolen <= CBLOCKSIZE);
					dbg("bindex %zu [chunk_iofrom %ju chunk_ioend %ju (%zu)]",
							index, chunk_iofrom, chunk_ioend, chunk_iolen);

					iov[index - index_sta].iov_base = chunk_iobuf;
					iov[index - index_sta].iov_len  = chunk_iolen;

					found = 1;
					break;
				}
			}

			if (!found)
				err("bug");
		}

	} else {
		iov_size = 1;
		iov = g_malloc0(sizeof(struct iovec));

		iov[0].iov_base = io->mbrs[ds->nlayers-1]->iobuf;
		iov[0].iov_len  = iolen;

		/* copy the start/end blocks of the region from a lower layer to the top layer */
		bool get_sta_block = false;
		bool get_end_block = false;

		if (iofrom % CBLOCKSIZE)
			if (!bitmap_test(ds->image[ds->nlayers-1]->bm, index_sta))
				get_sta_block = true;

		if (ioend % CBLOCKSIZE) {
			/*
			 * Handle the end of the io range is not aligned.
			 * Case 1: The IO range covers more than one block.
			 * Case 2: One block, but the start of the io range is aligned.
			 */
			if ((index_end > index_sta) ||
					((index_end == index_sta) && !get_sta_block))
				if (!bitmap_test(ds->image[ds->nlayers-1]->bm, index_end))
					get_end_block = true;

			/* bitmap_on() is performed in the below forloop */
		}

		if (get_sta_block)
			copy_block_to_top_layer(ds, io, index_sta, index_sta, ds->disksize);

		if (get_end_block)
			copy_block_to_top_layer(ds, io, index_end, index_sta, ds->disksize);


		for (unsigned long index = index_sta; index <= index_end; index++) {
			bitmap_on(ds->image[ds->nlayers-1]->bm, index);
		}
	}


	for (unsigned int i = 0; i < iov_size; i++) {
		dbg("iov %d: base %p len %zu", i, iov[i].iov_base, iov[i].iov_len);
	}

	io->iov = iov;
	io->iov_size = iov_size;

	return io;
}

void disk_stack_munmap(struct disk_stack_io *io)
{
	for (int i = 0; i < io->ds->nlayers; i++)
		mmap_block_region_free(io->mbrs[i]);

	g_free(io->iov);
	g_free(io);
}

void disk_stack_fsync(struct disk_stack *ds)
{
	int top = ds->nlayers - 1;
	int diskfd = ds->image[top]->diskfd;

	int ret = fsync(diskfd);
	if (ret < 0)
		err("fsync %m");
}

void disk_stack_punch_hole(struct disk_stack *ds, off_t iofrom, size_t iolen)
{
	int top = ds->nlayers - 1;
	int diskfd = ds->image[top]->diskfd;

	punch_hole(diskfd, iofrom, iolen);
}


#ifdef XNBD_LZO
/* See LZO.FAQ */
static inline size_t get_max_outlen(size_t input_block_size)
{
	/* Algorithm LZO1, LZO1A, LZO1B, LZO1C, LZO1F, LZO1X, LZO1Y, LZO1Z */
	size_t output_block_size = input_block_size + (input_block_size / 16) + 64 + 3;

	return output_block_size;
}

static unsigned char wrkmem[LZO1X_1_MEM_COMPRESS];

#if 0
void compress_iovec(struct iovec *iov, int count, uint32_t rawlen, char *cmpbuf, uint32_t *out_cmplen)
{
	unsigned char *rawbuf = g_malloc0(rawlen);
	int offset = 0;

	/* extract iovec to rawbuf */
	for (int i = 0; i < count; i++) {
		memcpy(rawbuf + offset, iov[i].iov_base, iov[i].iov_len);
		offset += iov[i].iov_len;
	}

	unsigned long cmplen;

	int ret = lzo1x_1_compress(rawbuf, rawlen, (unsigned char *) cmpbuf, &cmplen, wrkmem);
	if (ret == LZO_E_OK)
		info("compressed: %d -> %lu", rawlen, cmplen);
	else
		err("compression failed, %d", ret);

	*out_cmplen = cmplen;
}
#endif

#if 0
void compress_iovec_and_send(int csock, struct iovec *iov, unsigned int count)
{
	for (unsigned int i = 0; i < count; i++) {
		unsigned char *rawbuf = iov[i].iov_base;
		size_t rawlen       = iov[i].iov_len;

		unsigned char *cmpbuf = g_malloc0(get_max_outlen(rawlen));
		lzo_uint cmplen;

		int ret = lzo1x_1_compress(rawbuf, rawlen, cmpbuf, &cmplen, wrkmem);
		if (ret == LZO_E_OK)
			dbg("compressed: %d -> %lu", rawlen, cmplen);
		else
			err("compression failed, %d", ret);

		g_assert(cmplen <= UINT32_MAX && rawlen <= UINT32_MAX);
		unsigned long cmplen_n = htonl((uint32_t) cmplen);
		unsigned long rawlen_n = htonl((uint32_t) rawlen);

		net_send_all_or_abort(csock, &cmplen_n, sizeof(cmplen_n));
		net_send_all_or_abort(csock, &rawlen_n, sizeof(rawlen_n));

		net_send_all_or_abort(csock, cmpbuf, cmplen);

		g_free(cmpbuf);
	}
}
#endif

static int is_unicolor(unsigned char *buf, size_t len)
{
	int samebyte = 1;
	unsigned long *array = (unsigned long *) buf;
	unsigned long value = array[0];

	if (len % sizeof(unsigned long)) {
		warn("len %zu is not a multiple of sizeof(unsigned long). is_unicolor() returns false", len);
		return 0;
	}

	for (unsigned int i = 1; i < len / sizeof(unsigned long); i++) {
		if (value != array[i]) {
			samebyte = 0;
			break;
		}
	}

	return samebyte;
}

void compress_iovec_and_send_advanced(int csock, const struct iovec *iov, const unsigned int count, int lzo_enabled)
{
	// uint32_t count_n = htonl(count);
	// net_send_all_or_abort(csock, &count_n, sizeof(count_n));

	dbg("nchunks %u", count);

	for (unsigned int i = 0; i < count; i++) {
		unsigned char *rawbuf = iov[i].iov_base;
		size_t rawlen         = iov[i].iov_len;
		lzo_uint cmplen;

		if (is_unicolor(rawbuf, rawlen)) {
			dbg("%u / %u: unicolor", i, count);
			/* cmplen == 0 means the buffer will be filled with a uint32_t value. */
			cmplen = 0;

			uint32_t *array = (uint32_t *) rawbuf;
			uint32_t value = htonl(array[0]);

			uint32_t cmplen_n = htonl((uint32_t) cmplen);
			uint32_t rawlen_n = htonl((uint32_t) rawlen);
			net_send_all_or_abort(csock, &cmplen_n, sizeof(cmplen_n));
			net_send_all_or_abort(csock, &rawlen_n, sizeof(rawlen_n));

			net_send_all_or_abort(csock, &value, sizeof(value));

		} else {
			if (lzo_enabled) {
				dbg("%u / %u: lzo", i, count);
				unsigned char *cmpbuf = g_malloc0(get_max_outlen(rawlen));

				int ret = lzo1x_1_compress(rawbuf, rawlen, cmpbuf, &cmplen, wrkmem);
				if (ret == LZO_E_OK)
					dbg("compressed: %d -> %lu", rawlen, cmplen);
				else
					err("compression failed, %d", ret);

				g_assert(cmplen <= UINT32_MAX && rawlen <= UINT32_MAX);
				uint32_t cmplen_n = htonl((uint32_t) cmplen);
				uint32_t rawlen_n = htonl((uint32_t) rawlen);
				net_send_all_or_abort(csock, &cmplen_n, sizeof(cmplen_n));
				net_send_all_or_abort(csock, &rawlen_n, sizeof(rawlen_n));

				net_send_all_or_abort(csock, cmpbuf, cmplen);

				g_free(cmpbuf);

			} else {
				dbg("%u / %u: plain", i, count);

				cmplen = UINT32_MAX;

				uint32_t cmplen_n = htonl((uint32_t) cmplen);
				uint32_t rawlen_n = htonl((uint32_t) rawlen);
				net_send_all_or_abort(csock, &cmplen_n, sizeof(cmplen_n));
				net_send_all_or_abort(csock, &rawlen_n, sizeof(rawlen_n));

				net_send_all_or_abort(csock, rawbuf, rawlen);
			}
		}
	}
}

#else

void compress_iovec_and_send_advanced(int csock __attribute__((unused)),
	       	const struct iovec *iov __attribute__((unused)),
		const unsigned int count __attribute__((unused)),
		int lzo_enabled __attribute__((unused)))
{
	err("compression support was not compiled");
}

void compress_iovec_and_send(int csock __attribute__((unused)),
	       struct iovec *iov __attribute__((unused)),
	       int count __attribute__((unused)))
{
	err("lzo support was not compiled");
}
#endif




int target_mode_main_cow(struct xnbd_session *ses)
{
	struct xnbd_info *xnbd = ses->xnbd;

	struct nbd_reply reply;
	int csock = ses->clientfd;
	uint32_t iotype = 0;
	off_t iofrom = 0;
	size_t iolen  = 0;
	int ret;

	memset(&reply, 0, sizeof(reply));
	reply.magic = htonl(NBD_REPLY_MAGIC);
	reply.error = 0;


	ret = poll_request_arrival(ses);
	if (ret < 0)
		return -1;

	ret = nbd_server_recv_request(csock, xnbd->disksize, &iotype, &iofrom, &iolen, &reply);
	if (ret == NBD_SERVER_RECV__BAD_REQUEST) {
		net_send_all_or_abort(csock, &reply, sizeof(reply));
		return 0;
	} else if (ret == NBD_SERVER_RECV__MAGIC_MISMATCH)
		err("client bug: invalid header");
	else if (ret == NBD_SERVER_RECV__TERMINATE)
		return ret;


	int compression_enabled = 0;
	int compression_lzo = 0;
	if (iotype == NBD_CMD_READ_COMPRESS || iotype == NBD_CMD_READ_COMPRESS_LZO) {
		dbg("compression_enabled request");
		compression_enabled = 1;

		if (iotype == NBD_CMD_READ_COMPRESS_LZO) {
			compression_lzo = 1;
			dbg("lzo enabled");
		}

		iotype = NBD_CMD_READ;
	}


	if (xnbd->readonly) {
		if (iotype == NBD_CMD_WRITE || iotype == NBD_CMD_TRIM) {
			/* do not read following write data */
			err("%s to a readonly disk. disconnect.", nbd_get_iotype_string(iotype));
		}
	}


	dbg("direct mode");


	struct disk_stack_io *io = disk_stack_mmap(xnbd->cow_ds, iofrom, iolen, (iotype == NBD_CMD_READ));


	switch (iotype) {
		case NBD_CMD_WRITE:
			dbg("disk write iofrom %ju iolen %zu", iofrom, iolen);
#ifdef DEBUG_COW
			check_write();
			net_recv_all_or_abort(csock, debug_buf + iofrom, iolen);
			copy_buf_to_iov(io->iov, io->iov_size, debug_buf + iofrom, iolen);
			compare_iov_and_buf(io->iov, io->iov_size, debug_buf + iofrom, iolen);

#else
			net_readv_all_or_abort(csock, io->iov, io->iov_size);
#endif
			net_send_all_or_abort(csock, &reply, sizeof(reply));
			break;

		case NBD_CMD_READ:
			dbg("disk read iofrom %ju iolen %zu", iofrom, iolen);

			/* send normal header */
			net_send_all_or_abort(csock, &reply, sizeof(reply));

			if (compression_enabled) {
				/* send compressed data */
				compress_iovec_and_send_advanced(csock, io->iov, io->iov_size, compression_lzo);
			} else {
#ifdef DEBUG_COW
				compare_iov_and_buf(io->iov, io->iov_size, debug_buf + iofrom, iolen);
#endif
				net_writev_all_or_abort(csock, io->iov, io->iov_size);
			}

			break;

		case NBD_CMD_FLUSH:
			dbg("disk flush");

			disk_stack_fsync(xnbd->cow_ds);
			break;

		case NBD_CMD_TRIM:
			dbg("disk trim iofrom %ju iolen %zu", iofrom, iolen);

			disk_stack_punch_hole(xnbd->cow_ds, iofrom, iolen);
			break;

		default:
			err("unknown command in the cow-target mode, %u (%s)", iotype, nbd_get_iotype_string(iotype));
	}


	disk_stack_munmap(io);


	return 0;
}



int xnbd_cow_target_session_server(struct xnbd_session *ses)
{
	set_process_name("cow_wrk");
	//setup_debug_buf(ses->xnbd->ds);

	for (;;) {
		int ret = 0;

		ret = target_mode_main_cow(ses);
		if (ret < 0)
			return ret;
	}

	return 0;
}
