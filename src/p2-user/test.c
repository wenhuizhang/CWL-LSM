#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "cwlite.h"

int main( int argc, char *argv[] )
{
	int fd = cwlite_open( );
	printf("CWL: fd %d\n", fd );
	unsigned int cwl;
	int ret;

	cwl = cwlite_get( fd );
	printf("CWL: before %d\n", cwl );
	ret = cwlite_on( fd );
	cwl = cwlite_get( fd );
	printf("CWL: after on %d cwl is %d\n", ret, cwl );
	ret = cwlite_off( fd );
	cwl = cwlite_get( fd );
	printf("CWL: reset off %d cwl is %d\n", ret, cwl );
	cwlite_close( fd );

	return 0;
}
