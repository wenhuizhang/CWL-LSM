extern int cwlite_open( void );
extern int cwlite_close( int fd );

#define CWLSIZE  2

static inline int cwlite_on( int fd )
{
	int ret;

	if (fd < 0) return -2; 		// ERR: illegal fd

	printf("in cwlite_on\n");

	if ((lseek(fd, 0, SEEK_SET)) == 0) {   // reset file pointer to start
		printf("Setting CW-Lite ON\n");
  		ret = write(fd, "1", CWLSIZE); 
		if ( ret >= 0 ) return 1;
		else return -1;                // ERR: write failed 
	}

	return -3;  		// ERR: lseek failed
}


static inline int cwlite_off( int fd )
{
	int ret;

	if (fd < 0) return -2; 		// ERR: illegal fd

	printf("in cwlite_off\n");

	if ((lseek(fd, 0, SEEK_SET)) == 0) {   // reset file pointer to start
		printf("Setting CW-Lite OFF\n");
  		ret = write(fd, "0", CWLSIZE); 
		if ( ret >= 0 ) return 0;
		else return -1;                // ERR: write failed
	}

	return -3;  		// ERR: lseek failed
}


static inline int cwlite_get( int fd )
{
	int ret;
	char buf[12];

	if (fd < 0) return -2;   	// ERR: illegal fd

	if ((lseek(fd, 0, SEEK_SET)) == 0) {   // reset file pointer to start
  		ret = read(fd, buf, 12); 

		if ( ret > 0 ) {
			switch ( buf[0] ) {
			case '0':
				return 0;
				break;
			case '1':
				return 1;
				break;
			default:
				return -1;     // ERR: invalid value in cwlite
				break;
			}
		}
		else return -1; 	// ERR: read failed
	}

	return -3;  		// ERR: lseek failed to reset index
}



