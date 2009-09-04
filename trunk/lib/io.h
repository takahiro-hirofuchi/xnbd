/*
 * partially excerpted and modified from usbip.
 *
 * Copyright (C) 2005-2008 Takahiro Hirofuchi
 * Copyright (C) 2008-2009 National Institute of Advanced Industrial Science and Technology
 *
 * Author: Takahiro Hirofuchi
 */
#ifndef LIB_XNBD_IO_H
#define LIB_XNBD_IO_H

#include "common.h"
#include "net.h"
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>


void read_all(int fd, void *buf, size_t len);
void write_all(int fd, void *buf, size_t len);
void dump_buffer(const char *buff, int bufflen);
void dump_buffer_all(const char *buff, int bufflen);

pthread_t pthread_create_or_abort(void * (*start_routine)(void *), void *arg);

uint64_t get_disksize(int fd);
void calc_block_index(const uint32_t blocksize, uint64_t iofrom, uint32_t iolen, uint32_t *index_start, uint32_t *index_end);

char *get_line(int fd);
int put_line(int fd, char *msg);

#endif
