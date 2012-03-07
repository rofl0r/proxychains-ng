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
LOBJS = src/core.o src/libproxychains.o

CFLAGS  += -Wall -O0 -g -std=c99 -D_GNU_SOURCE -pipe -DTHREAD_SAFE
LDFLAGS = -shared -fPIC -ldl -lpthread
INC     = 
PIC     = -fPIC
AR      = $(CROSS_COMPILE)ar
RANLIB  = $(CROSS_COMPILE)ranlib

LDSO_SUFFIX = so
LD_SET_SONAME = -Wl,-soname=
INSTALL_FLAGS = -D -m

-include config.mak

LDSO_PATHNAME = libproxychains4.$(LDSO_SUFFIX)

SHARED_LIBS = $(LDSO_PATHNAME)
ALL_LIBS = $(SHARED_LIBS)
PXCHAINS = proxychains4
ALL_TOOLS = $(PXCHAINS)


CFLAGS+=$(USER_CFLAGS) $(MAC_CFLAGS)
CFLAGS_MAIN=-DLIB_DIR=\"$(libdir)\" -DSYSCONFDIR=\"$(sysconfdir)\" -DDLL_NAME=\"$(LDSO_PATHNAME)\"


all: $(ALL_LIBS) $(ALL_TOOLS)

#install: $(ALL_LIBS:lib/%=$(DESTDIR)$(libdir)/%) $(DESTDIR)$(LDSO_PATHNAME)
install: 
	install $(INSTALL_FLAGS) 755 $(ALL_TOOLS) $(DESTDIR)/$(bindir)/
	install $(INSTALL_FLAGS) 644 $(ALL_LIBS) $(DESTDIR)/$(libdir)/
	install $(INSTALL_FLAGS) 644 src/proxychains.conf $(DESTDIR)/$(sysconfdir)/

clean:
	rm -f $(ALL_LIBS)
	rm -f $(ALL_TOOLS)
	rm -f $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) $(CFLAGS_MAIN) $(INC) $(PIC) -c -o $@ $<

$(LDSO_PATHNAME): $(LOBJS)
	$(CC) $(LDFLAGS) $(LD_SET_SONAME)$(LDSO_PATHNAME) -o $@ $(LOBJS)

$(ALL_TOOLS): $(OBJS)
	$(CC) src/main.o -o $(PXCHAINS)


.PHONY: all clean install
