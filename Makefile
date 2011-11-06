#
# Makefile for proxychains (requires GNU make), stolen from musl
#
# Use config.mak to override any of the following variables.
# Do not make changes here.
#

exec_prefix = /usr/local
bindir = $(exec_prefix)/bin

prefix = /usr/local/
includedir = $(prefix)/include
libdir = $(prefix)/lib

SRCS = $(sort $(wildcard src/*.c))
OBJS = $(SRCS:.c=.o)
LOBJS = $(OBJS:.o=.lo)

CFLAGS  += -Wall -O0 -g -std=c99 -D_GNU_SOURCE -pipe -DTHREAD_SAFE
LDFLAGS = -shared -fPIC -ldl -lpthread
INC     = 
PIC     = -fPIC -O0
AR      = $(CROSS_COMPILE)ar
RANLIB  = $(CROSS_COMPILE)ranlib

LDSO_PATHNAME = libproxychains4.so

SHARED_LIBS = $(LDSO_PATHNAME)
ALL_LIBS = $(SHARED_LIBS)
PXCHAINS = proxychains4
ALL_TOOLS = $(PXCHAINS)


-include config.mak

CFLAGS_MAIN=-DLIB_DIR=\"$(libdir)\"


all: $(ALL_LIBS) $(ALL_TOOLS)

#install: $(ALL_LIBS:lib/%=$(DESTDIR)$(libdir)/%) $(DESTDIR)$(LDSO_PATHNAME)
install: 
	install -D -m 755 $(PXCHAINS) $(bindir)/$(PXCHAINS)
	install -D -m 644 $(LDSO_PATHNAME) $(libdir)
	install -D -m 644 src/proxychains.conf $(prefix)/etc

clean:
	rm -f $(OBJS)
	rm -f $(LOBJS)
	rm -f $(ALL_LIBS) lib/*.[ao] lib/*.so

%.o: %.c
	$(CC) $(CFLAGS) $(CFLAGS_MAIN) $(INC) -c -o $@ $<

%.lo: %.c
	$(CC) $(CFLAGS) $(CFLAGS_MAIN) $(INC) $(PIC) -c -o $@ $<

$(LDSO_PATHNAME): $(LOBJS)
	$(CC) $(LDFLAGS) -Wl,-soname=$(LDSO_PATHNAME) -o $@ $(LOBJS)

$(ALL_TOOLS): $(OBJS)
	$(CC) src/main.o -o $(PXCHAINS)


.PHONY: all clean install
