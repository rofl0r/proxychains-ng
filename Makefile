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
sysconfdir=$(prefix)/etc

SRCS = $(sort $(wildcard src/*.c))
OBJS = $(SRCS:.c=.o)
LOBJS = src/nameinfo.o \
        src/core.o src/common.o src/libproxychains.o src/shm.o \
        src/allocator_thread.o src/ip_type.o src/stringdump.o \
        src/hostentdb.o src/hash.o

CFLAGS  += -Wall -O0 -g -std=c99 -D_GNU_SOURCE -pipe
NO_AS_NEEDED = -Wl,--no-as-needed
LIBDL   = -ldl
LDFLAGS = -shared -fPIC $(NO_AS_NEEDED) $(LIBDL) -lpthread
INC     = 
PIC     = -fPIC
AR      = $(CROSS_COMPILE)ar
RANLIB  = $(CROSS_COMPILE)ranlib

LDSO_SUFFIX = so
LD_SET_SONAME = -Wl,-soname=
INSTALL_FLAGS = -D -m

LDSO_PATHNAME = libproxychains4.$(LDSO_SUFFIX)

SHARED_LIBS = $(LDSO_PATHNAME)
ALL_LIBS = $(SHARED_LIBS)
PXCHAINS = proxychains4
ALL_TOOLS = $(PXCHAINS)

-include config.mak

CFLAGS+=$(USER_CFLAGS) $(MAC_CFLAGS)
CFLAGS_MAIN=-DLIB_DIR=\"$(libdir)\" -DSYSCONFDIR=\"$(sysconfdir)\" -DDLL_NAME=\"$(LDSO_PATHNAME)\"


all: $(ALL_LIBS) $(ALL_TOOLS)

install-config:
	install -d $(DESTDIR)/$(sysconfdir)
	install $(INSTALL_FLAGS) 644 src/proxychains.conf $(DESTDIR)/$(sysconfdir)/

install: 
	install -d $(DESTDIR)/$(bindir)/ $(DESTDIR)/$(libdir)/
	install $(INSTALL_FLAGS) 755 $(ALL_TOOLS) $(DESTDIR)/$(bindir)/
	install $(INSTALL_FLAGS) 644 $(ALL_LIBS) $(DESTDIR)/$(libdir)/

clean:
	rm -f $(ALL_LIBS)
	rm -f $(ALL_TOOLS)
	rm -f $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) $(CFLAGS_MAIN) $(INC) $(PIC) -c -o $@ $<

$(LDSO_PATHNAME): $(LOBJS)
	$(CC) $(LDFLAGS) $(LD_SET_SONAME)$(LDSO_PATHNAME) -o $@ $(LOBJS)

$(ALL_TOOLS): $(OBJS)
	$(CC) src/main.o src/common.o -o $(PXCHAINS)


.PHONY: all clean install install-config
