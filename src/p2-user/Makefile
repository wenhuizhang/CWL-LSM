#
# File          : Makefile
# Description   : Build file for CMPSC497 project 1, applied cryptography
#                 


# Environment Setup
#LIBDIRS=-L. -L/opt/local/lib
#INCLUDES=-I. -I/opt/local/include
CC=gcc 
CFLAGS=-c $(INCLUDES) -g -Wall
LINK=gcc -g
LDFLAGS=$(LIBDIRS)
AR=ar rc
RANLIB=ranlib

# Suffix rules
.c.o :
	${CC} ${CFLAGS} $< -o $@

#
# Setup builds

TARGETS=cwl_test user_test
LIBS=

#
# Project Protections

p2-user : $(TARGETS)

cwl_test : test.o cwlite.o
	$(LINK) $(LDFLAGS) test.o cwlite.o $(LIBS) -o $@

user_test : user.o cwlite.o
	$(LINK) $(LDFLAGS) user.o cwlite.o $(LIBS) -o $@

clean:
	rm -f *.o *~ $(TARGETS)

BASENAME=p2-user
tar: 
	tar cvfz $(BASENAME).tgz -C ..\
	    $(BASENAME)/Makefile \
            $(BASENAME)/test.c \
	    $(BASENAME)/user.c \
	    $(BASENAME)/cwlite.h \
	    $(BASENAME)/cwlite.c 


