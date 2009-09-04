/*
 * Copyright (C) 2008-2009 National Institute of Advanced Industrial Science and Technology
 *
 * Author: Takahiro Hirofuchi
 */
#include "common.h"
#include "io.h"
#include "sys/mman.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <strings.h>
#include <string.h>
#include <errno.h>

uint32_t *bitmap_setup(uint32_t size);
uint32_t *bitmap_create(char *bitmapfile, uint32_t size, int *cbitmapfd, int *cbitmaplen);
int bitmap_test(uint32_t *bitmap_array, uint32_t block_index);
void bitmap_on(uint32_t *bitmap_array, uint32_t block_index);
