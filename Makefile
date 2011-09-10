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

CFLAGS  += -Wall -O0 -g -std=c99 -D_GNU_SOURCE -pipe 
LDFLAGS = -shared -fPIC -ldl
INC     = 
PIC     = -fPIC -O0
AR      = $(CROSS_COMPILE)ar
RANLIB  = $(CROSS_COMPILE)ranlib

SHARED_LIBS = libproxychains.so
ALL_LIBS = $(SHARED_LIBS)
ALL_TOOLS = proxychains

LDSO_PATHNAME = libproxychains.so.3

-include config.mak

CFLAGS_MAIN=-DLIB_DIR=\"$(libdir)\"


all: $(ALL_LIBS) $(ALL_TOOLS)

#install: $(ALL_LIBS:lib/%=$(DESTDIR)$(libdir)/%) $(DESTDIR)$(LDSO_PATHNAME)
install: 
	install -D -m 755 proxychains $(bindir)
	install -D -m 755 src/proxyresolv $(bindir)
	install -D -m 644 libproxychains.so $(libdir)
	install -D -m 644 src/proxychains.conf /etc
	ln -sf $(libdir)/libproxychains.so $(libdir)/libproxychains.so.3

clean:
	rm -f $(OBJS)
	rm -f $(LOBJS)
	rm -f $(ALL_LIBS) lib/*.[ao] lib/*.so

%.o: %.c
	$(CC) $(CFLAGS) $(CFLAGS_MAIN) $(INC) -c -o $@ $<

%.lo: %.c
	$(CC) $(CFLAGS) $(CFLAGS_MAIN) $(INC) $(PIC) -c -o $@ $<

libproxychains.so: $(LOBJS)
	$(CC) $(LDFLAGS) -Wl,-soname=libproxychains.so -o $@ $(LOBJS) -lgcc

$(ALL_TOOLS): $(OBJS)
	$(CC) src/main.o -o proxychains

$(DESTDIR)$(libdir)/%.so: %.so
	install -D -m 755 $< $@

$(DESTDIR)$(LDSO_PATHNAME): libproxychains.so
	ln -sf $(libdir)/libproxychains.so $@ || true

.PHONY: all clean install
