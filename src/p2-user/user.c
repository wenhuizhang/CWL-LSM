#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/xattr.h>
#include <assert.h>

#include "cwlite.h"

#define LIMIT 20

int main( int argc, char *argv[] )
{
	int cwl_fd, fd;
	unsigned int cwl;
	int ret;
	char buf1[LIMIT], buf2[LIMIT], attrbuf[LIMIT];

	assert( argc == 3 );

	cwl_fd = cwlite_open();
	assert( cwl_fd > 0 );

	fd = open(argv[1], O_RDONLY);

	if ( fd < 0 ) {
		printf( "user: %s open failed - probably no file\n", argv[1] );
	}
	else {
		ret = getxattr( argv[1], "security.sample", attrbuf, LIMIT );
		if ( ret > 0 ) {
			attrbuf[ret] = '\0';
			printf( "user: %s attribute %s\n", argv[1], attrbuf );
		}
		else {
			printf( "user: %s attribute retrieval problem\n", argv[1] );
		}
	}

	ret = read( fd, buf1, LIMIT );
	printf( "%s\n", buf1 );
	close( fd );

	cwlite_on( cwl_fd );
	fd = open(argv[2], O_RDONLY);
	cwlite_off( cwl_fd );

	if ( fd < 0 ) {
		printf( "user: %s open failed - probably no file\n", argv[2] );
	}
	else {
		ret = getxattr( argv[2], "security.sample", attrbuf, LIMIT );
		if ( ret > 0 ) {
			attrbuf[ret] = '\0';
			printf( "user: %s attribute %s\n", argv[2], attrbuf );
		}
		else {
			printf( "user: %s attribute retrieval problem\n", argv[2] );
		}
	}

	cwlite_on( cwl_fd );
	ret = read( fd, buf2, LIMIT );
	cwlite_off( cwl_fd );
	printf( "%s\n", buf2 );

	ret = read( fd, buf2, LIMIT );
	printf( "%s\n", buf2 );

	close( fd );
	cwlite_close( cwl_fd );
}
