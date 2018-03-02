#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "cwlite.h"

#define  SAMPLE_MNT  "/sys/kernel/debug/cwl"
#define  PATH_MAX    50
#define  VALSIZE     12

int cwlite_open( void )
{
  char path[PATH_MAX];
  int fd, ret;

  if (!SAMPLE_MNT) {
    errno = ENOENT;
    return -1;
  }

  snprintf(path, sizeof path, "%s/cwlite", SAMPLE_MNT);
  printf("Path: %s\n", path);
  fd = open(path, O_RDWR);
  if (fd < 0)
    return -1;

  printf("open: fd %d\n", fd);
  ret = cwlite_off( fd );
  printf("open: after off %d\n", ret);

  if (ret < 0)
    return -1;
  return fd;
}


int cwlite_close( int fd )
{
  int ret;

  ret = close(fd);
  printf("close: fd: %d; ret %d\n", fd, ret);
  return ret;
}
