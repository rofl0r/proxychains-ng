int __res_ninit() {
	return 0;
}

void __pthread_register_cancel(void* p) {

}

void __pthread_unregister_cancel(void *p) {

}

#include <setjmp.h>
int __sigsetjmp(sigjmp_buf buf, int save) {
	return sigsetjmp(buf, save);
}

static __thread void* thread_arg;
static __thread int (*thread_compar)(const void*, const void*, void*);
static int my_thread_compare_func(const void* a, const void* b) {
	return thread_compar(a, b, thread_arg);
}
#include <stddef.h>
#include <stdlib.h>
void qsort_r(void* base, size_t nmemb, size_t size, int (*compar)(const void*, const void*, void*), void *arg) {
	thread_arg = arg;
	thread_compar = compar;
	return qsort(base, nmemb, size, my_thread_compare_func);
}

int backtrace(void **buffer, int size) {
	return 0;
}

char **backtrace_symbols(void *const *buffer, int size) {
	return 0;
}

#include <pthread.h>
int __register_atfork(void (*prepare) (void), void (*parent) (void), void (*child) (void), void * __dso_handle) {
	return pthread_atfork(prepare, parent, child);
}

#define _GNU_SOURCE
#include <poll.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>
#include <wchar.h>

__attribute((noreturn)) void __chk_fail(void)
{
	write(2, "buffer overflow detected\n", 25);
	abort();
}

int __asprintf_chk(char **s, int flag, const char *fmt, ...)
{
	va_list ap;
	int r;
	va_start(ap,fmt);
	r = vasprintf(s, fmt, ap);
	va_end(ap);
	return r;
}

size_t __confstr_chk(int name, char *buf, size_t len, size_t size)
{
	return confstr(name, buf, len);
}

int __dprintf_chk(int fd, int flag, const char *fmt, ...)
{
	va_list ap;
	int r;
	va_start(ap,fmt);
	r = vdprintf(fd, fmt, ap);
	va_end(ap);
	return r;
}

char *__fgets_chk(char *s, size_t size, int n, FILE *f)
{
	return fgets(s, n, f);
}

char *__fgets_unlocked_chk(char *s, size_t size, int n, FILE *f)
{
	return fgets_unlocked(s, n, f);
}

wchar_t *__fgetws_chk(wchar_t *s, size_t size, int n, FILE *f)
{
	return fgetws(s, n, f);
}

wchar_t *fgetws_unlocked(wchar_t *, int, FILE *);

wchar_t *__fgetws_unlocked_chk(wchar_t *s, size_t size, int n, FILE *f)
{
	return fgetws_unlocked(s, n, f);
}

int __fprintf_chk(FILE *f, int flag, const char *fmt, ...)
{
	va_list ap;
	int r;
	va_start(ap,fmt);
	r = vfprintf(f, fmt, ap);
	va_end(ap);
	return r;
}

int __fwprintf_chk(FILE *f, int flag, const wchar_t *fmt, ...)
{
	va_list ap;
	int r;
	va_start(ap,fmt);
	r = vfwprintf(f, fmt, ap);
	va_end(ap);
	return r;
}

size_t __fread_chk(void *p, size_t size, size_t sz, size_t n, FILE *f)
{
	return fread(p, sz, n, f);
}

size_t __fread_unlocked_chk(void *p, size_t size, size_t sz, size_t n, FILE *f)
{
	return fread_unlocked(p, sz, n, f);
}

char *__getcwd_chk(char *buf, size_t len, size_t size)
{
	return getcwd(buf, len);
}

int __getdomainname_chk(char *buf, size_t len, size_t size)
{
	return getdomainname(buf, len);
}

int __getgroups_chk(int n, gid_t *list, size_t listlen)
{
	return getgroups(n, list);
}

int __gethostname_chk(char *buf, size_t len, size_t size)
{
	return gethostname(buf, len);
}

int __getlogin_r_chk(char *buf, size_t len, size_t size)
{
	return getlogin_r(buf, len);
}

char *__gets_chk(char *buf, size_t size)
{
	return gets(buf);
}

__attribute((noreturn)) void __longjmp_chk(jmp_buf buf, int v)
{
	longjmp(buf, v);
}

size_t __mbsnrtowcs_chk(wchar_t *dst, const char **src, size_t n, size_t len, mbstate_t *st, size_t dstsize)
{
	return mbsnrtowcs(dst, src, n, len, st);
}

size_t __mbsrtowcs_chk(wchar_t *dst, const char **src, size_t len, mbstate_t *st, size_t dstsize)
{
	return mbsrtowcs(dst, src, len, st);
}

size_t __mbstowcs_chk(wchar_t *dst, const char *src, size_t len, size_t dstsize)
{
	return mbstowcs(dst, src, len);
}

void *__memcpy_chk(void *dst, void *src, size_t len, size_t dstsize)
{
	return memcpy(dst, src, len);
}

void *__mempcpy_chk(void *dst, void *src, size_t len, size_t dstsize)
{
	return mempcpy(dst, src, len);
}

void *__memmove_chk(void *dst, void *src, size_t len, size_t dstsize)
{
	return memmove(dst, src, len);
}

void *__memset_chk(void *s, int c, size_t n, size_t size)
{
	return memset(s, c, n);
}

int __poll_chk(struct pollfd *fds, nfds_t n, int timeout, size_t fdslen)
{
	return poll(fds, n, timeout);
}

int __ppoll_chk(struct pollfd *fds, nfds_t n, const struct timespec *timeout, const sigset_t *mask, size_t fdslen)
{
	return ppoll(fds, n, timeout, mask);
}

ssize_t __pread_chk(int fd, void *buf, size_t n, off_t off, size_t bufsize)
{
	return pread(fd, buf, n, off);
}

#undef weak_alias
#define weak_alias(old, new) \
        extern __typeof(old) new __attribute__((weak, alias(#old)))

weak_alias(__pread_chk, __pread64_chk);

int __printf_chk(int flag, const char *fmt, ...)
{
	va_list ap;
	int r;
	va_start(ap,fmt);
	r = vprintf(fmt, ap);
	va_end(ap);
	return r;
}

int __ptsname_r_chk(int fd, char *buf, size_t len, size_t size)
{
	return ptsname_r(fd, buf, len);
}

ssize_t __read_chk(int fd, void *buf, size_t n, size_t bufsize)
{
	return read(fd, buf, n);
}

ssize_t __readlinkat_chk(int fd, const char *path, void *buf, size_t n, size_t bufsize)
{
	return readlinkat(fd, path, buf, n);
}

ssize_t __readlink_chk(const char *path, void *buf, size_t n, size_t bufsize)
{
	return readlink(path, buf, n);
}

char *__realpath_chk(const char *name, char *resolved, size_t resolvedsize)
{
	return realpath(name, resolved);
}

ssize_t __recv_chk(int fd, void *buf, size_t n, size_t bufsize, int flags)
{
	return recv(fd, buf, n, flags);
}

ssize_t __recvfrom_chk(int fd, void *buf, size_t n, size_t bufsize, int flags, struct sockaddr *addr, socklen_t *addrlen)
{
	return recvfrom(fd, buf, n, flags, addr, addrlen);
}

int __sprintf_chk(char *s, int flag, size_t size, const char *fmt, ...)
{
	va_list ap;
	int r;
	va_start(ap,fmt);
	r = vsprintf(s, fmt, ap);
	va_end(ap);
	return r;
}

int __snprintf_chk(char *s, size_t n, int flag, size_t size, const char *fmt, ...)
{
	va_list ap;
	int r;
	va_start(ap,fmt);
	r = vsnprintf(s, n, fmt, ap);
	va_end(ap);
	return r;
}

char *__stpcpy_chk(char *dst, const char *src, size_t dstsize)
{
	return stpcpy(dst, src);
}
char *__stpncpy_chk(char *dst, const char *src, size_t n, size_t dstsize)
{
	return stpncpy(dst, src, n);
}

char *__strcat_chk(char *dst, const char *src, size_t dstsize)
{
	return strcat(dst, src);
}

char *__strcpy_chk(char *dst, const char *src, size_t dstsize)
{
	return strcpy(dst, src);
}

char *__strncat_chk(char *dst, const char *src, size_t n, size_t dstsize)
{
	return strncat(dst, src, n);
}

char *__strncpy_chk(char *dst, const char *src, size_t n, size_t dstsize)
{
	return strncpy(dst, src, n);
}

int __swprintf_chk(wchar_t *s, size_t n, int flag, size_t size, const wchar_t *fmt, ...)
{
	va_list ap;
	int r;
	va_start(ap,fmt);
	r = vswprintf(s, n, fmt, ap);
	va_end(ap);
	return r;
}

void __syslog_chk(int pri, int flag, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsyslog(pri, fmt, ap);
	va_end(ap);
}

int __ttyname_r_chk(int fd, char *buf, size_t len, size_t size)
{
	return ttyname_r(fd, buf, len);
}

int __vasprintf_chk(char **s, int flag, const char *fmt, va_list ap)
{
	return vasprintf(s, fmt, ap);
}

int __vdprintf_chk(int fd, int flag, const char *fmt, va_list ap)
{
	return vdprintf(fd, fmt, ap);
}

int __vfprintf_chk(FILE *f, int flag, const char *fmt, va_list ap)
{
	return vfprintf(f, fmt, ap);
}

int __vfwprintf_chk(FILE *f, int flag, const wchar_t *fmt, va_list ap)
{
	return vfwprintf(f, fmt, ap);
}

int __vprintf_chk(int flag, const char *fmt, va_list ap)
{
	return vprintf(fmt, ap);
}

int __vsnprintf_chk(char *s, size_t n, int flag, size_t size, const char *fmt, va_list ap)
{
	return vsnprintf(s, n, fmt, ap);
}

int __vsprintf_chk(char *s, int flag, size_t size, const char *fmt, va_list ap)
{
	return vsprintf(s, fmt, ap);
}

int __vswprintf_chk(wchar_t *s, size_t n, int flag, size_t size, const wchar_t *fmt, va_list ap)
{
	return vswprintf(s, n, fmt, ap);
}

void __vsyslog_chk(int pri, int flag, const char *fmt, va_list ap)
{
	vsyslog(pri, fmt, ap);
}

int __vwprintf_chk(int flag, const wchar_t *fmt, va_list ap)
{
	return vwprintf(fmt, ap);
}

wchar_t *__wcpcpy_chk(wchar_t *dst, const wchar_t *src, size_t dstsize)
{
	return wcpcpy(dst, src);
}

wchar_t *__wcpncpy_chk(wchar_t *dst, const wchar_t *src, size_t n, size_t dstsize)
{
	return wcpncpy(dst, src, n);
}

size_t __wcrtomb_chk(char *s, wchar_t c, mbstate_t *st, size_t size)
{
	return wcrtomb(s, c, st);
}

wchar_t *__wcscat_chk(wchar_t *dst, const wchar_t *src, size_t dstlen)
{
	return wcscat(dst, src);
}

wchar_t *__wcscpy_chk(wchar_t *dst, const wchar_t *src, size_t dstlen)
{
	return wcscpy(dst, src);
}

wchar_t *__wcsncat_chk(wchar_t *dst, const wchar_t *src, size_t n, size_t dstlen)
{
	return wcsncat(dst, src, n);
}

wchar_t *__wcsncpy_chk(wchar_t *dst, const wchar_t *src, size_t n, size_t dstlen)
{
	return wcsncpy(dst, src, n);
}

size_t __wcsnrtombs_chk(char *dst, const wchar_t **src, size_t n, size_t len, mbstate_t *st, size_t dstsize)
{
	return wcsnrtombs(dst, src, n, len, st);
}

size_t __wcsrtombs_chk(char *dst, const wchar_t **src, size_t len, mbstate_t *st, size_t dstsize)
{
	return wcsrtombs(dst, src, len, st);
}

size_t __wcstombs_chk(char *dst, const wchar_t *src, size_t len, size_t dstsize)
{
	return wcstombs(dst, src, len);
}

int __wctomb_chk(char *s, wchar_t c, size_t size)
{
	return wctomb(s, c);
}

wchar_t *__wmemcpy_chk(wchar_t *dst, const wchar_t *src, size_t n, size_t dstlen)
{
	return wmemcpy(dst, src, n);
}

wchar_t *__wmemmove_chk(wchar_t *dst, const wchar_t *src, size_t n, size_t dstlen)
{
	return wmemmove(dst, src, n);
}

wchar_t *__wmempcpy_chk(wchar_t *dst, const wchar_t *src, size_t n, size_t dstlen)
{
	return mempcpy(dst, src, n*sizeof*src);
}

wchar_t *__wmemset_chk(wchar_t *s, wchar_t c, size_t n, size_t slen)
{
	return wmemset(s, c, n);
}

int __wprintf_chk(int flag, const wchar_t *fmt, ...)
{
	va_list ap;
	int r;
	va_start(ap,fmt);
	r = vwprintf(fmt, ap);
	va_end(ap);
	return r;
}

