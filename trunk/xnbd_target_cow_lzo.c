/* 
 * Copyright (C) 2008-2010 National Institute of Advanced Industrial Science and Technology
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

	char *buf = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED)
		err("mmap debug_buf, %m");

	close(fd);

	debug_buf = g_malloc0(len);

	memcpy(debug_buf, buf, len);

	int ret = munmap(buf, len);
	if (ret < 0)
		err("munmap");

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
	check_disksize(diskpath, disksize);

	struct disk_stack *ds = g_malloc0(sizeof(struct disk_stack));
	ds->nlayers = 1;
	ds->disksize = disksize;

	struct disk_image *di = g_malloc0(sizeof(struct disk_image));
	di->diskfd = diskfd;
	di->path = g_strdup(diskpath);

	// snprintf(di->bmpath, PATH_MAX, "%s.bm", diskpath);
	unsigned long nblocks = get_disk_nblocks(ds->disksize);

	// di->bmpath = g_strdup_printf("%s.bm", diskpath);


	/* get a unique di->bmpath */
	for (;;) {
		long int suffix = random();
		di->bmpath = g_strdup_printf("/dev/shm/xnbd-server-cow-base-%lx.bm", suffix);

		int fd = open(di->bmpath, O_RDWR | O_CREAT | O_EXCL, 0600);
		if (fd < 0) {
			g_free(di->bmpath);
			continue;
		} else {
			close(fd);
			break;
		}
	}

	{
		info("create new base bitmap %s", di->bmpath);
		size_t tmp_bmlen;
		unsigned long *tmp_bm = bitmap_open_file(di->bmpath, nblocks, &tmp_bmlen, 0, 1);
		info("bitmap file %s filled by 1", di->bmpath);
		memset(tmp_bm, 0xff, tmp_bmlen);  /* catch all blocks (2nd arg is converted to unsigned char) */
		bitmap_close_file(tmp_bm, tmp_bmlen);
	}

#if 0
	{
		/* A CoW stack needs the bitmap filled by 1, which is
		 * coupled with the base target file. */
		struct stat st;
		int ret = stat(di->bmpath, &st);
		if (ret == 0) {
			info("use alreay-existing bitmap %s", di->bmpath);
		} else {
			info("create new base bitmap %s", di->bmpath);
			size_t tmp_bmlen;
			unsigned long *tmp_bm = bitmap_open_file(di->bmpath, nblocks, &tmp_bmlen, 0, 1);
			info("bitmap file %s filled by 1", di->bmpath);
			memset(tmp_bm, 0xff, tmp_bmlen);  /* catch all blocks (2nd arg is converted to unsigned char) */
			bitmap_close_file(tmp_bm, tmp_bmlen);
		}
	}
#endif

	/* open an existing bitmap file as readonly */
	di->bm = bitmap_open_file(di->bmpath, nblocks, &di->bmlen, 1, 0);

	unlink(di->bmpath);


	ds->image[0] = di;

	info("disk_stack[0] %s %s", di->path, di->bmpath);

	return ds;
}

void destroy_disk_stack(struct disk_stack *ds)
{
	for (int i = 0; i < ds->nlayers; i++) {
		struct disk_image *di = ds->image[i];
		close(di->diskfd);

		if (di->bm) {
			int ret = msync(di->bm, di->bmlen, MS_SYNC);
			if (ret < 0)
				err("msync");

			ret = munmap(di->bm, di->bmlen);
			if (ret < 0)
				err("munmap");
		}

		g_free(di->path);
		g_free(di->bmpath);

		g_free(di);
	}

	g_free(ds);
}


void disk_stack_add_image(struct disk_stack *ds, char *diskpath, int newfile)
{
	int diskfd;
	off_t disksize;

	if (ds->nlayers == MAX_DISKIMAGESTACK)
		err("no space");

	diskfd = open(diskpath, O_RDWR | O_CREAT, 0644);
	if (diskfd < 0) {
		if (errno == EOVERFLOW)
			warn("enable large file support!");
		err("open, %s", strerror(errno));
	}

	disksize = get_disksize(diskfd);
	if (disksize != ds->disksize) {
		warn("ftruncate %s (%ju -> %ju)", diskpath, disksize, ds->disksize);
		int ret = ftruncate(diskfd, ds->disksize);
		if (ret < 0)
			err("ftruncate");
	}

	struct disk_image *di = g_malloc0(sizeof(struct disk_image));
	di->diskfd = diskfd;
	di->path = g_strdup(diskpath);

	di->bmpath = g_strdup_printf("%s.bm", diskpath);

	if (newfile)
		di->bm = bitmap_open_file(di->bmpath, get_disk_nblocks(ds->disksize), &di->bmlen, 0, 1);
	else 
		di->bm = bitmap_open_file(di->bmpath, get_disk_nblocks(ds->disksize), &di->bmlen, 1, 0);


	info("disk_stack[%d] %s %s", ds->nlayers, di->path, di->bmpath);

	ds->image[ds->nlayers] = di;
	ds->nlayers += 1;
}

static void update_block_with_found(struct disk_stack *ds, struct disk_stack_io *io, unsigned long index, unsigned long start_index)
{
	int found = 0;

	//info("called %u", index);

	for (int i = ds->nlayers - 1; i >= 0; i--) {
		struct disk_image *di = ds->image[i];

		if (bitmap_test(di->bm, index)) {
			dbg("index %u found at layer %d", index, i);

			char *dstptr = io->bufs[ds->nlayers - 1] + CBLOCKSIZE * (index - start_index);
			char *srcptr = io->bufs[i] + CBLOCKSIZE * (index - start_index);

			memcpy(dstptr, srcptr, CBLOCKSIZE);

			found = 1;
			break;
		}
	}

	if (!found)
		err("bug");
}


struct disk_stack *open_cow_disk(char *diskpath, int newfile, int cowid)
{
	struct disk_stack *ds = create_disk_stack(diskpath);
	
	char *cowpath;

	if (newfile) {
		/* get a unique di->bmpath */
		for (;;) {
			cowpath = g_strdup_printf("%s.cow%d.layer%d", diskpath, cowid, ds->nlayers - 1);

			int fd = open(cowpath, O_RDWR | O_CREAT | O_EXCL, 0600);
			if (fd < 0) {
				cowid += 1;
				g_free(cowpath);
				continue;
			} else {
				close(fd);
				break;
			}
		}
	} else 
		cowpath = g_strdup_printf("%s.cow%d.layer%d", diskpath, cowid, ds->nlayers - 1);


	disk_stack_add_image(ds, cowpath, newfile);

	g_free(cowpath);

	return ds;
}

void close_cow_disk(struct disk_stack *ds, int delete_cow)
{
	info("close cow disk");

	if (delete_cow) {
		struct disk_image *di_cow = ds->image[ds->nlayers - 1];

		int ret = unlink(di_cow->path);
		if (ret < 0)
			err("unlink %m");

		ret = unlink(di_cow->bmpath);
		if (ret < 0)
			err("unlink %m");
	}

	destroy_disk_stack(ds);
}



static struct disk_stack_io *create_disk_stack_io(struct disk_stack *ds)
{
	struct disk_stack_io *io = g_malloc0(sizeof(struct disk_stack_io));
	io->ds = ds;

	return io;
}

void free_disk_stack_io(struct disk_stack_io *io)
{
	for (int i = 0; i < io->ds->nlayers; i++) {
		int ret = munmap(io->bufs[i], io->buflen);
		if (ret < 0)
			err("munmap");
	}
	g_free(io->iov);
}

struct disk_stack_io *disk_stack_mmap(struct disk_stack *ds, off_t iofrom, size_t iolen, int reading)
{
	unsigned long index_start, index_end;

	get_io_range_index(iofrom, iolen, &index_start, &index_end);

	dbg("iofrom %llu iofrom + iolen %llu", iofrom, iofrom + iolen);
	dbg("index_start %u end %u", index_start, index_end);

	/* need casting to off_t */
	off_t mapping_start  = (off_t) index_start * CBLOCKSIZE;
	size_t mapping_length = (index_end - index_start + 1) * CBLOCKSIZE;

	//dbg("%u * %u = %llu", index_start, CBLOCKSIZE, mapping_start);

	dbg("mmapping_start %ju mapping_end %ju mapping_length %zu", 
			mapping_start, mapping_start + mapping_length,
			mapping_length);


	struct disk_stack_io *io = create_disk_stack_io(ds);

	/* mmap() all layers */
	for (int i = 0; i < ds->nlayers; i++) {
		struct disk_image *di = ds->image[i];

		int flags = PROT_READ;
		if (i == ds->nlayers -1)
		       flags |=	PROT_WRITE;

		io->bufs[i] = mmap(NULL, mapping_length, flags, MAP_SHARED, di->diskfd, mapping_start);
		if (io->bufs[i] == MAP_FAILED)
			err("mmap, %m");

		io->buflen  = mapping_length;

		dbg("mmap %d %s, disk %ju - %ju => buf %p - %p", i, di->path, mapping_start, mapping_start + mapping_length,
				io->bufs[i], io->bufs[i] + io->buflen);
	}


	struct iovec *iov = NULL;
	unsigned int iov_size = 0;

	if (reading) {
		/* the number of iovec in readv()'s args is int */
		g_assert((index_end - index_start + 1) <= UINT32_MAX);

		iov_size = (unsigned int) (index_end - index_start + 1);
		iov = g_new0(struct iovec, iov_size);

		for (unsigned long index = index_start; index <= index_end; index++) {
			unsigned long iofrom_inbuf = 0;
			unsigned long iolen_inbuf = 0;

			/* should we uint64_t?, but how much does overhead come in 32-bit arch? */

			iofrom_inbuf = (unsigned long) ((off_t) index * CBLOCKSIZE - mapping_start);
			iolen_inbuf  = CBLOCKSIZE;

			if (index_start == index_end) {
				iofrom_inbuf = (unsigned long) (iofrom - mapping_start);
				iolen_inbuf  = iolen;
			} else {
				if (index == index_start) {
					iofrom_inbuf = (unsigned long) (iofrom - mapping_start);
					iolen_inbuf  = CBLOCKSIZE - iofrom_inbuf;

				} else if (index == index_end) {
					iofrom_inbuf = (unsigned long) ((off_t) index * CBLOCKSIZE - mapping_start);
					iolen_inbuf  = (unsigned long) ((iofrom + iolen) - (index * CBLOCKSIZE));
				}
			}


			
			dbg("index %lu, iofrom_inbuf %lu iolen_inbuf %lu", index, iofrom_inbuf, iolen_inbuf);

			int found = 0;

			for (int i = ds->nlayers - 1; i >= 0; i--) {
				struct disk_image *di = ds->image[i];

				if (bitmap_test(di->bm, index)) {
					dbg("index %u found at layer %d", index, i);

					iov[index - index_start].iov_base = io->bufs[i] + iofrom_inbuf;
					iov[index - index_start].iov_len  = iolen_inbuf;

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

		unsigned long iofrom_inbuf = (unsigned long) (iofrom - mapping_start);

		iov[0].iov_base = io->bufs[ds->nlayers-1] + iofrom_inbuf;
		iov[0].iov_len  = iolen;


		/*
		 * First, send read requests for start/end blocks to a source node
		 * if they are partial blocks and not yet cached.
		 **/
		int get_start_block = 0;
		int get_end_block   = 0;

		if (iofrom % CBLOCKSIZE)
			if (!bitmap_test(ds->image[ds->nlayers-1]->bm, index_start)) 
				get_start_block = 1;


		if ((iofrom + iolen) % CBLOCKSIZE) {
			/*
			 * Handle the end of the io range is not aligned.
			 * Case 1: The IO range covers more than one block.
			 * Case 2: One block, but the start of the io range is aligned.
			 */
			if ((index_end > index_start) ||
					((index_end == index_start) && !get_start_block))
				if (!bitmap_test(ds->image[ds->nlayers-1]->bm, index_end)) 
					get_end_block = 1;

			/* bitmap_on() is performed in the below forloop */
		}

		if (get_start_block)
			update_block_with_found(ds, io, index_start, index_start);

		if (get_end_block)
			update_block_with_found(ds, io, index_end, index_start);



		for (unsigned long index = index_start; index <= index_end; index++) {
			bitmap_on(ds->image[ds->nlayers-1]->bm, index);
		}
	}


	for (unsigned int i = 0; i < iov_size; i++) {
		dbg("iov %d: base %p len %d", i, iov[i].iov_base, iov[i].iov_len);
	}

	io->iov = iov;
	io->iov_size = iov_size;

	return io;
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

#else

void compress_iovec_and_send(int csock, struct iovec *iov, int count)
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

	bzero(&reply, sizeof(reply));
	reply.magic = htonl(NBD_REPLY_MAGIC);
	reply.error = 0;


	ret = poll_request_arrival(ses);
	if (ret < 0)
		return -1;

	ret = nbd_server_recv_request(csock, xnbd->disksize, &iotype, &iofrom, &iolen, &reply);
	if (ret == -1) {
		net_send_all_or_abort(csock, &reply, sizeof(reply));
		return 0;
	} else if (ret == -2)
		err("client bug: invalid header");
	else if (ret == -3)
		return ret;

	/* the MSB of iotype is a xnbd's special flag for lzo compression */
	uint32_t lzo_enabled = iotype >> (sizeof(iotype) - 1);
	iotype = iotype & 0x7fffffff;  /* clear flag */
	if (lzo_enabled)
		dbg("lzo_enabled request");


	if (xnbd->readonly && iotype == NBD_CMD_WRITE) {
		/* do not read following write data */
		err("NBD_CMD_WRITE to a readonly disk. disconnect.");
	}

	dbg("direct mode");


	struct disk_stack_io *io = disk_stack_mmap(xnbd->ds, iofrom, iolen, (iotype == NBD_CMD_READ));


	switch (iotype) {
		case NBD_CMD_WRITE:
			dbg("disk write iofrom %llu iolen %u", iofrom, iolen);
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
			dbg("disk read iofrom %llu iolen %u", iofrom, iolen);

			if (lzo_enabled) {
				uint32_t nchunks = htonl(io->iov_size);

				/* send normal header */
				net_send_all_or_abort(csock, &reply, sizeof(reply));

				/* send compressed data */
				net_send_all_or_abort(csock, &nchunks, sizeof(nchunks));
				compress_iovec_and_send(csock, io->iov, io->iov_size);

			} else {
				net_send_all_or_abort(csock, &reply, sizeof(reply));

#ifdef DEBUG_COW
				compare_iov_and_buf(io->iov, io->iov_size, debug_buf + iofrom, iolen);
#endif
				net_writev_all_or_abort(csock, io->iov, io->iov_size);
			}

			break;

		default:
			err("unknown command %u", iotype);
	}


	free_disk_stack_io(io);


#if 0
	if (iotype == NBD_CMD_READ)
		gstat_add(xnbd, iofrom);
#endif

	return 0;
}



int target_server_cow(struct xnbd_session *ses)
{
	//setup_debug_buf(ses->xnbd->ds);

	for (;;) {
		int ret = 0;

		ret = target_mode_main_cow(ses);
		if (ret < 0)
			return ret;
	}

	return 0;
}
