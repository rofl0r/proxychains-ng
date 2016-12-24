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
LOBJS = src/nameinfo.o src/version.o \
        src/core.o src/common.o src/libproxychains.o \
        src/allocator_thread.o src/ip_type.o \
        src/hostsreader.o src/hash.o src/debug.o

GENH = src/version.h

CFLAGS  += -Wall -O0 -g -std=c99 -D_GNU_SOURCE -pipe
NO_AS_NEEDED = -Wl,--no-as-needed
LIBDL   = -ldl
LDFLAGS = -fPIC $(NO_AS_NEEDED) $(LIBDL) -lpthread
INC     = 
PIC     = -fPIC
AR      = $(CROSS_COMPILE)ar
RANLIB  = $(CROSS_COMPILE)ranlib

LDSO_SUFFIX = so
LD_SET_SONAME = -Wl,-soname=
INSTALL = ./tools/install.sh

LDSO_PATHNAME = libproxychains4.$(LDSO_SUFFIX)

SHARED_LIBS = $(LDSO_PATHNAME)
ALL_LIBS = $(SHARED_LIBS)
PXCHAINS = proxychains4
ALL_TOOLS = $(PXCHAINS)
ALL_CONFIGS = src/proxychains.conf

-include config.mak

CFLAGS+=$(USER_CFLAGS) $(MAC_CFLAGS)
CFLAGS_MAIN=-DLIB_DIR=\"$(libdir)\" -DSYSCONFDIR=\"$(sysconfdir)\" -DDLL_NAME=\"$(LDSO_PATHNAME)\"


all: $(ALL_LIBS) $(ALL_TOOLS)

install: install-libs install-tools

$(DESTDIR)$(bindir)/%: %
	$(INSTALL) -D -m 755 $< $@

$(DESTDIR)$(libdir)/%: %
	$(INSTALL) -D -m 644 $< $@

$(DESTDIR)$(sysconfdir)/%: src/%
	$(INSTALL) -D -m 644 $< $@

install-libs: $(ALL_LIBS:%=$(DESTDIR)$(libdir)/%)
install-tools: $(ALL_TOOLS:%=$(DESTDIR)$(bindir)/%)
install-config: $(ALL_CONFIGS:src/%=$(DESTDIR)$(sysconfdir)/%)

clean:
	rm -f $(ALL_LIBS)
	rm -f $(ALL_TOOLS)
	rm -f $(OBJS)
	rm -f $(GENH)

src/version.h: $(wildcard VERSION .git)
	printf '#define VERSION "%s"\n' "$$(sh tools/version.sh)" > $@

src/version.o: src/version.h

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_MAIN) $(INC) $(PIC) -c -o $@ $<

$(LDSO_PATHNAME): $(LOBJS)
	$(CC) $(LDFLAGS) $(LD_SET_SONAME)$(LDSO_PATHNAME) $(USER_LDFLAGS) \
		-shared -o $@ $(LOBJS)

$(ALL_TOOLS): $(OBJS)
	$(CC) src/main.o src/common.o $(USER_LDFLAGS) -o $(PXCHAINS)


.PHONY: all clean install install-config install-libs install-tools
