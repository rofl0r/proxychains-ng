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
sysconfdir = $(prefix)/etc
zshcompletiondir = $(prefix)/share/zsh/site-functions

OBJS = src/common.o src/main.o

DOBJS = src/daemon/hsearch.o \
        src/daemon/sblist.o src/daemon/sblist_delete.o \
        src/daemon/daemon.o src/daemon/udpserver.o

LOBJS = src/version.o \
        src/core.o src/common.o src/libproxychains.o \
        src/allocator_thread.o src/rdns.o \
        src/hostsreader.o src/hash.o src/debug.o


GENH = src/version.h

CFLAGS  += -Wall -O0 -g -std=c99 -D_GNU_SOURCE -pipe
NO_AS_NEEDED = -Wl,--no-as-needed
LDFLAGS = -fPIC $(NO_AS_NEEDED) $(LIBDL) $(PTHREAD)
INC     = 
PIC     = -fPIC
AR      = $(CROSS_COMPILE)ar
RANLIB  = $(CROSS_COMPILE)ranlib
SOCKET_LIBS =

LDSO_SUFFIX = so
LD_SET_SONAME = -Wl,-soname=
INSTALL = ./tools/install.sh

LDSO_PATHNAME = libproxychains4.$(LDSO_SUFFIX)

SHARED_LIBS = $(LDSO_PATHNAME)
ALL_LIBS = $(SHARED_LIBS)
PXCHAINS = proxychains4
PXCHAINS_D = proxychains4-daemon
ALL_TOOLS = $(PXCHAINS) $(PXCHAINS_D)
ALL_CONFIGS = src/proxychains.conf
ZSH_COMPLETION = completions/zsh/_proxychains4

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

$(DESTDIR)$(zshcompletiondir)/%: completions/zsh/%
	$(INSTALL) -D -m 644 $< $@

install-libs: $(ALL_LIBS:%=$(DESTDIR)$(libdir)/%)
install-tools: $(ALL_TOOLS:%=$(DESTDIR)$(bindir)/%)
install-config: $(ALL_CONFIGS:src/%=$(DESTDIR)$(sysconfdir)/%)
install-zsh-completion: $(ZSH_COMPLETION:completions/zsh/%=$(DESTDIR)$(zshcompletiondir)/%)

clean:
	rm -f $(ALL_LIBS)
	rm -f $(ALL_TOOLS)
	rm -f $(OBJS) $(LOBJS) $(DOBJS)
	rm -f $(GENH)

src/version.h: $(wildcard VERSION .git)
	printf '#define VERSION "%s"\n' "$$(sh tools/version.sh)" > $@

src/version.o: src/version.h

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_MAIN) $(INC) $(PIC) -c -o $@ $<

$(LDSO_PATHNAME): $(LOBJS)
	$(CC) $(LDFLAGS) $(FAT_LDFLAGS) $(LD_SET_SONAME)$(LDSO_PATHNAME) \
		$(USER_LDFLAGS) -shared -o $@ $^ $(SOCKET_LIBS)

$(PXCHAINS): $(OBJS)
	$(CC) $^ $(FAT_BIN_LDFLAGS) $(USER_LDFLAGS) $(LIBDL) -o $@

$(PXCHAINS_D): $(DOBJS)
	$(CC) $^ $(FAT_BIN_LDFLAGS) $(USER_LDFLAGS) -o $@


.PHONY: all clean install install-config install-libs install-tools install-zsh-completion
