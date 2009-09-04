/* 
 * Copyright (C) 2008-2009 National Institute of Advanced Industrial Science and Technology
 */
#include "xnbd.h"

int main(int argc, char **argv)
{
	if (argc < 2)
		return 1;

	cachestat_dump_loop(argv[1], 2);

	return 0;
}
