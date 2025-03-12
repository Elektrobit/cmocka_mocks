// SPDX-License-Identifier: MIT
#ifndef __MOCK_LIBC_H__
#define __MOCK_LIBC_H__

// clang-format off
// because this order is a cmocka requirement
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <cmocka.h>
// clang-format on

#include <cmocka_extensions/cmocka_extensions.h>
#include <cmocka_extensions/mock_extensions.h>
#include <cmocka_extensions/mock_func_wrap.h>
#include <dirent.h>
#include <libgen.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <regex.h>
#include <semaphore.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

MOCK_FUNC_PROTOTYPE(dirname, char *, char *path)
MOCK_FUNC_PROTOTYPE(mkdir, int, const char *pathname, mode_t mode)
MOCK_FUNC_PROTOTYPE(readlink, ssize_t, const char *pathname, char *buf, size_t bufsiz)
MOCK_FUNC_PROTOTYPE(unlink, int, const char *pathname)
MOCK_FUNC_PROTOTYPE(regcomp, int, regex_t *preg, const char *regex, int cflags)
MOCK_FUNC_PROTOTYPE(regerror, size_t, int errcode, const regex_t *preg, char *errbuf, size_t errbuf_size)
MOCK_FUNC_PROTOTYPE(regexec, int, const regex_t *preg, const char *string, size_t nmatch, regmatch_t pmatch[],
                    int eflags)
MOCK_FUNC_PROTOTYPE(malloc, void *, size_t size)
MOCK_FUNC_PROTOTYPE(realloc, void *, void *ptr, size_t newSize)
MOCK_FUNC_PROTOTYPE(calloc, void *, size_t nmemb, size_t size)
MOCK_FUNC_PROTOTYPE(free, void, void *ptr)
MOCK_FUNC_PROTOTYPE(memcpy, void *, void *destination, const void *source, size_t num)
MOCK_FUNC_PROTOTYPE(strdup, char *, const char *string)
MOCK_FUNC_PROTOTYPE(strndup, char *, const char *string, size_t n)
extern int MOCK_FUNC_WRAP(access_errno);
MOCK_FUNC_PROTOTYPE(access, int, const char *pathname, int mode)
extern int MOCK_FUNC_WRAP(ftruncate_errno);
MOCK_FUNC_PROTOTYPE(ftruncate, int, int fd, off_t length)
MOCK_FUNC_PROTOTYPE(fopen, FILE *, const char *filename, const char *mode)
MOCK_FUNC_PROTOTYPE(fdopen, FILE *, const int fd, const char *mode)
MOCK_FUNC_PROTOTYPE(fclose, int, FILE *stream)
MOCK_FUNC_PROTOTYPE(fwrite, size_t, const void *ptr, size_t size, size_t count, FILE *stream)
MOCK_FUNC_PROTOTYPE(fread, size_t, void *ptr, size_t size, size_t count, FILE *stream)
MOCK_FUNC_PROTOTYPE(scandir, int, const char *dirp, struct dirent ***namelist, int (*filter)(const struct dirent *),
                    int (*compar)(const struct dirent **, const struct dirent **))
MOCK_FUNC_PROTOTYPE(fseek, int, FILE *stream, long int offset, int origin)
MOCK_FUNC_PROTOTYPE(rewind, void, FILE *stream)
MOCK_FUNC_PROTOTYPE(ftell, long int, FILE *stream)
MOCK_FUNC_PROTOTYPE(popen, FILE *, const char *command, const char *type)
MOCK_FUNC_PROTOTYPE(pclose, int, FILE *stream)
MOCK_FUNC_PROTOTYPE(getline, ssize_t, char **lineptr, size_t *n, FILE *stream)
MOCK_FUNC_PROTOTYPE(getenv, char *, const char *name)
MOCK_FUNC_PROTOTYPE(getpid, pid_t)
MOCK_FUNC_PROTOTYPE(opendir, DIR *, const char *nam)
MOCK_FUNC_PROTOTYPE(closedir, int, DIR *dirp)
MOCK_FUNC_PROTOTYPE(remove, int, const char *filename)
MOCK_FUNC_PROTOTYPE(readdir, struct dirent *, DIR *dirp)
MOCK_FUNC_PROTOTYPE(stat, int, const char *pathname, struct stat *statbuf)
MOCK_FUNC_PROTOTYPE(fputc, int, int character, FILE *stream)
MOCK_FUNC_PROTOTYPE(time, time_t, time_t *timer)
MOCK_FUNC_PROTOTYPE(clock_gettime, int, clockid_t clock_id, struct timespec *tp)
MOCK_FUNC_PROTOTYPE(inet_aton, int, const char *cp, struct in_addr *inp)
MOCK_FUNC_PROTOTYPE(inet_pton, int, int af, const char *cp, void *buf)
MOCK_FUNC_PROTOTYPE(getaddrinfo, int, const char *node, const char *service, const struct addrinfo *hints,
                    struct addrinfo **res)
MOCK_FUNC_PROTOTYPE(freeaddrinfo, void, struct addrinfo *res)
MOCK_FUNC_PROTOTYPE(socket, int, int domain, int type, int protocol)
MOCK_FUNC_PROTOTYPE(getsockopt, int, int fd, int level, int optname, void *optval, socklen_t *optlen)
MOCK_FUNC_PROTOTYPE(setsockopt, int, int fd, int level, int optname, const void *optval, socklen_t optlen)
extern int MOCK_FUNC_WRAP(accept_errno);
MOCK_FUNC_PROTOTYPE(accept, int, int fd, __SOCKADDR_ARG addr, socklen_t *len)
MOCK_FUNC_PROTOTYPE(connect, int, int fd, const struct sockaddr *addr, socklen_t len)
MOCK_FUNC_PROTOTYPE(bind, int, int fd, __CONST_SOCKADDR_ARG addr, socklen_t len)
MOCK_FUNC_PROTOTYPE(listen, int, int fd, int n)
MOCK_FUNC_PROTOTYPE(close, int, int fd)
MOCK_FUNC_PROTOTYPE(open, int, char *file, int flags, ...)
extern int MOCK_FUNC_WRAP(pselect_errno);
MOCK_FUNC_PROTOTYPE(pselect, int, int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                    const struct timespec *timeout, const __sigset_t *sigmask)
MOCK_FUNC_PROTOTYPE(raise, int, int __sig)
MOCK_FUNC_PROTOTYPE(pthread_create, int, pthread_t *__newthread, const pthread_attr_t *__attr,
                    void *(*__start_routine)(void *), void *__arg)
MOCK_FUNC_PROTOTYPE(pthread_once, int, pthread_once_t *__once_control, void (*__init_routine)(void))
MOCK_FUNC_PROTOTYPE(pthread_join, int, pthread_t __th, void **__thread_return)
MOCK_FUNC_PROTOTYPE(pthread_mutex_init, int, pthread_mutex_t *__mutex, const pthread_mutexattr_t *__mutexattr)
MOCK_FUNC_PROTOTYPE(pthread_mutex_destroy, int, pthread_mutex_t *__mutex)
MOCK_FUNC_PROTOTYPE(pthread_mutex_trylock, int, pthread_mutex_t *__mutex)
MOCK_FUNC_PROTOTYPE(pthread_mutex_lock, int, pthread_mutex_t *__mutex)
MOCK_FUNC_PROTOTYPE(pthread_mutex_unlock, int, pthread_mutex_t *__mutex)
MOCK_FUNC_PROTOTYPE(pthread_mutex_timedlock, int, pthread_mutex_t *__mutex, const struct timespec *__abstime)
MOCK_FUNC_PROTOTYPE(pthread_setname_np, int, pthread_t thread, const char *name)
MOCK_FUNC_PROTOTYPE(sem_init, int, sem_t *__sem, int __pshared, unsigned int __value)
MOCK_FUNC_PROTOTYPE(sem_post, int, sem_t *__sem)
MOCK_FUNC_PROTOTYPE(sem_destroy, int, sem_t *__sem)
MOCK_FUNC_PROTOTYPE(sem_timedwait, int, sem_t *__sem, const struct timespec *__abstime)

MOCK_FUNC_PROTOTYPE(eventfd, int, unsigned int __count, int __flags)
MOCK_FUNC_PROTOTYPE(eventfd_read, int, int __fd, eventfd_t *__value)
MOCK_FUNC_PROTOTYPE(eventfd_write, int, int __fd, eventfd_t __value)

#endif
