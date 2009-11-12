/* 
 * Copyright (C) 2008-2009 National Institute of Advanced Industrial Science and Technology
 */
#include "xnbd.h"


char tmppath[PATH_MAX];
struct disk_stack *create_disk_stack(char *diskpath)
{
	int diskfd;
	uint64_t disksize;

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
	di->path = diskpath;

	snprintf(tmppath, PATH_MAX, "%s.bm", diskpath);
	di->bm = bitmap_create(tmppath, ds->disksize / CBLOCKSIZE, &di->bmfd, &di->bmlen);
	memset(di->bm, 0xff, di->bmlen);  /* catch all blocks */

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

			close(di->bmfd);
		}

		g_free(di);
	}

	g_free(ds);
}


void disk_stack_add_image(struct disk_stack *ds, char *diskpath)
{
	int diskfd;
	uint64_t disksize;

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
		warn("ftruncate %s (%llu -> %llu)", diskpath, disksize, ds->disksize);
		int ret = ftruncate(diskfd, ds->disksize);
		if (ret < 0)
			err("ftruncate");
	}

	struct disk_image *di = g_malloc0(sizeof(struct disk_image));
	di->diskfd = diskfd;
	di->path = diskpath;

	snprintf(di->bmpath, PATH_MAX, "%s.bm", diskpath);
	di->bm = bitmap_create(di->bmpath, ds->disksize / CBLOCKSIZE, &di->bmfd, &di->bmlen);

	info("disk_stack[%d] %s %s", ds->nlayers, di->path, di->bmpath);

	ds->image[ds->nlayers] = di;
	ds->nlayers += 1;
}



void setup_cow_disk(char *diskpath, struct xnbd_info *xnbd)
{
	struct disk_stack *ds = create_disk_stack(diskpath);


	xnbd->cowpath = g_malloc0(PATH_MAX);
	snprintf(xnbd->cowpath, PATH_MAX, "%s.cow%d", diskpath, ds->nlayers -1);
	disk_stack_add_image(ds, xnbd->cowpath);

	xnbd->ds = ds;
	xnbd->disksize = ds->disksize;
}

struct disk_stack_io *create_disk_stack_io(struct disk_stack *ds)
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

struct disk_stack_io *disk_stack_mmap(struct disk_stack *ds, uint64_t iofrom, uint32_t iolen, int reading)
{
	uint32_t index_start, index_end;

	get_io_range_index(iofrom, iolen, &index_start, &index_end);

	dbg("iofrom %llu iofrom + iolen %llu", iofrom, iofrom + iolen);
	dbg("index_start %u end %u", index_start, index_end);

	/* (uint64_t) casting is essential !!! */
	uint64_t mapping_start  = ((uint64_t) index_start) * CBLOCKSIZE;
	uint32_t mapping_length = (index_end - index_start + 1) * CBLOCKSIZE;

	//dbg("%u * %u = %llu", index_start, CBLOCKSIZE, mapping_start);

	dbg("mmapping_start %llu mapping_end %llu mapping_length %u", 
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

		dbg("mmap %d %s, disk %llu - %llu => buf %p - %p", i, di->path, mapping_start, mapping_start + mapping_length,
				io->bufs[i], io->bufs[i] + io->buflen);
	}


	struct iovec *iov = NULL;
	int iov_size = 0;

	if (reading) {
		iov_size = (index_end - index_start + 1);
		iov = g_malloc0((sizeof(struct iovec)) * iov_size);

		for (uint32_t index = index_start; index <= index_end; index++) {
			uint32_t iofrom_inbuf = 0;
			uint32_t iolen_inbuf = 0;

			iofrom_inbuf = index * CBLOCKSIZE - mapping_start;
			iolen_inbuf  = CBLOCKSIZE;

			if (index_start == index_end) {
				iofrom_inbuf = iofrom - mapping_start;
				iolen_inbuf  = iolen;
			} else {
				if (index == index_start) {
					iofrom_inbuf = iofrom - mapping_start;
					iolen_inbuf  = CBLOCKSIZE - iofrom_inbuf;

				} else if (index == index_end) {
					iofrom_inbuf = index * CBLOCKSIZE - mapping_start;
					iolen_inbuf  = (iofrom + iolen) - (index * CBLOCKSIZE);
				}
			}


			
			dbg("index %u, iofrom_inbuf %u iolen_inbuf %u", index, iofrom_inbuf, iolen_inbuf);

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

		uint32_t iofrom_inbuf = iofrom - mapping_start;

		iov[0].iov_base = io->bufs[ds->nlayers-1] + iofrom_inbuf;
		iov[0].iov_len  = iolen;

		for (uint32_t index = index_start; index <= index_end; index++) {
			bitmap_on(ds->image[ds->nlayers-1]->bm, index);
		}
	}


	for (int i = 0; i < iov_size; i++) {
		dbg("iov %d: base %p len %d", i, iov[i].iov_base, iov[i].iov_len);
	}

	io->iov = iov;
	io->iov_size = iov_size;

	return io;
}


int target_mode_main_cow(struct xnbd_session *ses)
{
	struct xnbd_info *xnbd = ses->xnbd;

	struct nbd_reply reply;
	int csock = ses->clientfd;
	uint32_t iotype = 0;
	uint64_t iofrom = 0;
	uint32_t iolen  = 0;
	int ret;

	bzero(&reply, sizeof(reply));
	reply.magic = htonl(NBD_REPLY_MAGIC);
	reply.error = 0;


	ret = poll_request_arrival(ses);
	if (ret < 0)
		return -1;

	ret = recv_request(csock, xnbd->disksize, &iotype, &iofrom, &iolen, &reply);
	if (ret == -1) {
		net_send_all_or_abort(csock, &reply, sizeof(reply));
		return 0;
	} else if (ret == -2)
		err("client bug: invalid header");
	else if (ret == -3)
		return ret;

	if (xnbd->readonly && iotype == NBD_CMD_WRITE) {
		/* do not read following write data */
		err("NBD_CMD_WRITE to a readonly disk. disconnect.");
	}

	dbg("direct mode");


	struct disk_stack_io *io = disk_stack_mmap(xnbd->ds, iofrom, iolen, (iotype == NBD_CMD_READ));


	switch (iotype) {
		case NBD_CMD_WRITE:
			dbg("disk write iofrom %llu iolen %u", iofrom, iolen);

			net_readv_all_or_abort(csock, io->iov, io->iov_size);

			net_send_all_or_abort(csock, &reply, sizeof(reply));

			break;

		case NBD_CMD_READ:
			dbg("disk read iofrom %llu iolen %u", iofrom, iolen);

			net_send_all_or_abort(csock, &reply, sizeof(reply));
			net_writev_all_or_abort(csock, io->iov, io->iov_size);

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
	for (;;) {
		int ret = 0;

		ret = target_mode_main_cow(ses);
		if (ret < 0)
			return ret;
	}

	return 0;
}
