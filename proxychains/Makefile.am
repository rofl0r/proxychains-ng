SUBDIRS = docs 

EXTRA_DIST = proxychains.conf core.c core.h libproxychains.c 

sysconf_DATA=$(srcdir)/proxychains.conf

install-data-local:
	$(mkinstalldirs) ${DESTDIR}${bindir}
	${INSTALL} $(srcdir)/proxychains  ${DESTDIR}${bindir}/proxychains
	${INSTALL} $(srcdir)/proxyresolv ${DESTDIR}${bindir}/proxyresolv

uninstall-local:
	-rm -f ${DESTDIR}${bindir}/proxychains
	-rm -f ${DESTDIR}${bindir}/proxyresolv

#bin_PROGRAMS = proxychains

#proxychains_SOURCES = main.c

# set the include path found by configure
INCLUDES= $(all_includes)

#proxychains_LDFLAGS = $(all_libraries)
lib_LTLIBRARIES = libproxychains.la
libproxychains_la_LDFLAGS = -version-info 3:0:0 $(all_libraries)
libproxychains_la_LIBADD= -ldl
noinst_HEADERS = core.h
libproxychains_la_SOURCES= libproxychains.c core.c
libproxychains_la_METASOURCES = USE_AUTOMOC



#install-private: install
#	$(mkinstalldirs) $(HOME)/bin
#	$(INSTALL_DATA) $(srcdir)/proxychains $(HOME)/bin/proxychains
#
#uninstall-private: uninstall
#	-rm -f $(HOME)/bin/proxychains
