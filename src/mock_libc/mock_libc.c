// SPDX-License-Identifier: MIT

#include "cmocka_mocks/mock_libc.h"

#include <cmocka.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

MOCK_FUNC_VAR_NEW(regcomp);
int MOCK_FUNC_WRAP(regcomp)(regex_t *preg, const char *regex, int cflags) {
    int result;

    switch (MOCK_GET_TYPE(regcomp)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(regcomp)(preg, regex, cflags);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(preg);
            check_expected_ptr(regex);
            check_expected(cflags);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(regcomp)(preg, regex, cflags);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(regerror);
size_t MOCK_FUNC_WRAP(regerror)(int errcode, const regex_t *preg, char *errbuf, size_t errbuf_size) {
    size_t result;

    switch (MOCK_GET_TYPE(regerror)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(regerror)(errcode, preg, errbuf, errbuf_size);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(errcode);
            check_expected_ptr(preg);
            check_expected_ptr(errbuf);
            check_expected(errbuf_size);
            result = mock_type(size_t);
            break;
        default:
            result = MOCK_FUNC_REAL(regerror)(errcode, preg, errbuf, errbuf_size);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(regexec);
int MOCK_FUNC_WRAP(regexec)(const regex_t *preg, const char *string, size_t nmatch, regmatch_t pmatch[], int eflags) {
    int result;

    switch (MOCK_GET_TYPE(regexec)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(regexec)(preg, string, nmatch, pmatch, eflags);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(preg);
            check_expected_ptr(string);
            check_expected(nmatch);
            check_expected_ptr(pmatch);
            check_expected_ptr(eflags);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(regexec)(preg, string, nmatch, pmatch, eflags);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(malloc);
void *MOCK_FUNC_WRAP(malloc)(size_t size) {
    void *result;

    switch (MOCK_GET_TYPE(malloc)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(malloc)(size);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(size);
            result = mock_ptr_type(void *);
            break;
        default:
            result = MOCK_FUNC_REAL(malloc)(size);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(realloc);
void *MOCK_FUNC_WRAP(realloc)(void *ptr, size_t newSize) {
    void *result;

    switch (MOCK_GET_TYPE(realloc)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(realloc)(ptr, newSize);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(ptr);
            check_expected(newSize);
            result = mock_ptr_type(void *);
            break;
        default:
            result = MOCK_FUNC_REAL(realloc)(ptr, newSize);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(calloc);
void *MOCK_FUNC_WRAP(calloc)(size_t nmemb, size_t size) {
    void *result;

    switch (MOCK_GET_TYPE(calloc)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(calloc)(nmemb, size);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(nmemb);
            check_expected(size);
            result = mock_ptr_type(void *);
            break;
        default:
            result = MOCK_FUNC_REAL(calloc)(nmemb, size);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(free);
void MOCK_FUNC_WRAP(free)(void *ptr) {
    switch (MOCK_GET_TYPE(free)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            MOCK_FUNC_WITH(free)(ptr);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(ptr);
            break;
        default:
            MOCK_FUNC_REAL(free)(ptr);
            break;
    }
}

MOCK_FUNC_VAR_NEW(memcpy);
void *MOCK_FUNC_WRAP(memcpy)(void *destination, const void *source, size_t num) {
    void *result;

    switch (MOCK_GET_TYPE(memcpy)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(memcpy)(destination, source, num);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(destination);
            check_expected(source);
            check_expected(num);
            result = mock_ptr_type(void *);
            break;
        default:
            result = MOCK_FUNC_REAL(memcpy)(destination, source, num);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(strdup);
char *MOCK_FUNC_WRAP(strdup)(const char *string) {
    char *result;

    switch (MOCK_GET_TYPE(strdup)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(strdup)(string);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(string);
            result = mock_ptr_type(char *);
            break;
        default:
            result = MOCK_FUNC_REAL(strdup)(string);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(strndup);
char *MOCK_FUNC_WRAP(strndup)(const char *string, size_t n) {
    char *result;

    switch (MOCK_GET_TYPE(strndup)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(strndup)(string, n);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(string);
            check_expected(n);
            result = mock_ptr_type(char *);
            break;
        default:
            result = MOCK_FUNC_REAL(strndup)(string, n);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(fopen);
FILE *MOCK_FUNC_WRAP(fopen)(const char *filename, const char *mode) {
    FILE *result;

    switch (MOCK_GET_TYPE(fopen)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(fopen)(filename, mode);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(filename);
            check_expected_ptr(mode);
            result = mock_ptr_type(FILE *);
            break;
        default:
            result = MOCK_FUNC_REAL(fopen)(filename, mode);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(fdopen);
FILE *MOCK_FUNC_WRAP(fdopen)(const int fd, const char *mode) {
    FILE *result;

    switch (MOCK_GET_TYPE(fdopen)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(fdopen)(fd, mode);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(fd);
            check_expected_ptr(mode);
            result = mock_ptr_type(FILE *);
            break;
        default:
            result = MOCK_FUNC_REAL(fdopen)(fd, mode);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(fclose);
int MOCK_FUNC_WRAP(fclose)(FILE *stream) {
    int result;

    switch (MOCK_GET_TYPE(fclose)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(fclose)(stream);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(stream);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(fclose)(stream);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(fwrite);
size_t MOCK_FUNC_WRAP(fwrite)(const void *ptr, size_t size, size_t count, FILE *stream) {
    size_t result;

    switch (MOCK_GET_TYPE(fwrite)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(fwrite)(ptr, size, count, stream);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(ptr);
            check_expected(size);
            check_expected(count);
            check_expected_ptr(stream);
            result = mock_type(size_t);
            break;
        default:
            result = MOCK_FUNC_REAL(fwrite)(ptr, size, count, stream);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(fread);
size_t MOCK_FUNC_WRAP(fread)(void *ptr, size_t size, size_t count, FILE *stream) {
    size_t result;

    switch (MOCK_GET_TYPE(fread)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(fread)(ptr, size, count, stream);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(ptr);
            check_expected(size);
            check_expected(count);
            check_expected_ptr(stream);
            result = mock_type(size_t);
            break;
        default:
            result = MOCK_FUNC_REAL(fread)(ptr, size, count, stream);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(scandir);
int MOCK_FUNC_WRAP(scandir)(const char *dirp, struct dirent ***namelist, int (*filter)(const struct dirent *),
                            int (*compar)(const struct dirent **, const struct dirent **)) {
    int result;

    switch (MOCK_GET_TYPE(scandir)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(scandir)(dirp, namelist, filter, compar);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(dirp);
            check_expected_ptr(namelist);
            check_expected_ptr(filter);
            check_expected_ptr(compar);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(scandir)(dirp, namelist, filter, compar);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(access);
int MOCK_FUNC_WRAP(access)(const char *pathname, int mode) {
    int result;

    switch (MOCK_GET_TYPE(access)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(access)(pathname, mode);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(pathname);
            check_expected(mode);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(access)(pathname, mode);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(fseek);
int MOCK_FUNC_WRAP(fseek)(FILE *stream, long int offset, int origin) {
    int result;

    switch (MOCK_GET_TYPE(fseek)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(fseek)(stream, offset, origin);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(stream);
            check_expected(offset);
            check_expected(origin);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(fseek)(stream, offset, origin);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(rewind);
void MOCK_FUNC_WRAP(rewind)(FILE *stream) {
    switch (MOCK_GET_TYPE(rewind)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            MOCK_FUNC_WITH(rewind)(stream);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(stream);
            break;
        default:
            MOCK_FUNC_REAL(rewind)(stream);
            break;
    }
}

MOCK_FUNC_VAR_NEW(ftell);
long int MOCK_FUNC_WRAP(ftell)(FILE *stream) {
    long int result;

    switch (MOCK_GET_TYPE(ftell)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(ftell)(stream);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(stream);
            result = mock_type(long);
            break;
        default:
            result = MOCK_FUNC_REAL(ftell)(stream);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(popen);
FILE *MOCK_FUNC_WRAP(popen)(const char *command, const char *type) {
    FILE *result;

    switch (MOCK_GET_TYPE(popen)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(popen)(command, type);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(command);
            check_expected_ptr(type);
            result = mock_ptr_type(FILE *);
            break;
        default:
            result = MOCK_FUNC_REAL(popen)(command, type);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(pclose);
int MOCK_FUNC_WRAP(pclose)(FILE *stream) {
    int result;

    switch (MOCK_GET_TYPE(pclose)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(pclose)(stream);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(stream);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(pclose)(stream);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(getline);
ssize_t MOCK_FUNC_WRAP(getline)(char **lineptr, size_t *n, FILE *stream) {
    ssize_t result;

    switch (MOCK_GET_TYPE(getline)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(getline)(lineptr, n, stream);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(lineptr);
            check_expected(n);
            check_expected_ptr(stream);
            result = mock_type(ssize_t);
            break;
        default:
            result = MOCK_FUNC_REAL(getline)(lineptr, n, stream);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(getenv);
char *MOCK_FUNC_WRAP(getenv)(const char *name) {
    char *result;

    switch (MOCK_GET_TYPE(getenv)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(getenv)(name);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(name);
            result = mock_ptr_type(char *);
            break;
        default:
            result = MOCK_FUNC_REAL(getenv)(name);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(getpid);
pid_t MOCK_FUNC_WRAP(getpid)() {
    pid_t result;

    switch (MOCK_GET_TYPE(getpid)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(getpid)();
            break;
        case CMOCKA_MOCK_ENABLED:
            result = mock_type(pid_t);
            break;
        default:
            result = MOCK_FUNC_REAL(getpid)();
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(opendir);
DIR *MOCK_FUNC_WRAP(opendir)(const char *name) {
    DIR *result;

    switch (MOCK_GET_TYPE(opendir)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(opendir)(name);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(name);
            result = mock_type(DIR *);
            break;
        default:
            result = MOCK_FUNC_REAL(opendir)(name);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(closedir);
int MOCK_FUNC_WRAP(closedir)(DIR *dirp) {
    int result;

    switch (MOCK_GET_TYPE(closedir)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(closedir)(dirp);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(dirp);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(closedir)(dirp);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(remove);
int MOCK_FUNC_WRAP(remove)(const char *filename) {
    int result;

    switch (MOCK_GET_TYPE(remove)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(remove)(filename);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(filename);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(remove)(filename);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(readdir);
struct dirent *MOCK_FUNC_WRAP(readdir)(DIR *dirp) {
    struct dirent *result;

    switch (MOCK_GET_TYPE(readdir)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(readdir)(dirp);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(dirp);
            result = mock_type(struct dirent *);
            break;
        default:
            result = MOCK_FUNC_REAL(readdir)(dirp);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(stat);
int MOCK_FUNC_WRAP(stat)(const char *pathname, struct stat *statbuf) {
    int result;

    switch (MOCK_GET_TYPE(stat)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(stat)(pathname, statbuf);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(pathname);
            check_expected_ptr(statbuf);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(stat)(pathname, statbuf);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(fputc);
int MOCK_FUNC_WRAP(fputc)(int character, FILE *stream) {
    int result;

    switch (MOCK_GET_TYPE(fputc)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(fputc)(character, stream);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(character);
            check_expected_ptr(stream);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(fputc)(character, stream);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(time);
time_t MOCK_FUNC_WRAP(time)(time_t *timer) {
    time_t result;

    switch (MOCK_GET_TYPE(time)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(time)(timer);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(timer);
            if (timer != NULL) {
                *timer = mock_type(time_t);
            }
            result = mock_type(time_t);
            break;
        default:
            result = MOCK_FUNC_REAL(time)(timer);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(clock_gettime);
int MOCK_FUNC_WRAP(clock_gettime)(clockid_t clock_id, struct timespec *tp) {
    int result;

    switch (MOCK_GET_TYPE(clock_gettime)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(clock_gettime)(clock_id, tp);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(clock_id);
            check_expected_ptr(tp);
            memcpy(tp, mock_ptr_type(struct timespec *), sizeof(struct timespec));
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(clock_gettime)(clock_id, tp);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(inet_aton);
int MOCK_FUNC_WRAP(inet_aton)(const char *cp, struct in_addr *inp) {
    int result;

    switch (MOCK_GET_TYPE(inet_aton)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(inet_aton)(cp, inp);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(cp);
            check_expected_ptr(inp);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(inet_aton)(cp, inp);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(inet_pton);
int MOCK_FUNC_WRAP(inet_pton)(int af, const char *cp, void *buf) {
    int result;

    switch (MOCK_GET_TYPE(inet_pton)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(inet_pton)(af, cp, buf);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(af);
            check_expected_ptr(cp);
            check_expected_ptr(buf);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(inet_pton)(af, cp, buf);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(getaddrinfo);
int MOCK_FUNC_WRAP(getaddrinfo)(const char *node, const char *service, const struct addrinfo *hints,
                                struct addrinfo **res) {
    int result;

    switch (MOCK_GET_TYPE(getaddrinfo)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(getaddrinfo)(node, service, hints, res);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(node);
            check_expected_ptr(service);
            check_expected_ptr(hints);
            *res = mock_ptr_type(struct addrinfo *);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(getaddrinfo)(node, service, hints, res);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(freeaddrinfo);
void MOCK_FUNC_WRAP(freeaddrinfo)(struct addrinfo *res) {
    switch (MOCK_GET_TYPE(freeaddrinfo)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            MOCK_FUNC_WITH(freeaddrinfo)(res);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(res);
            break;
        default:
            MOCK_FUNC_REAL(freeaddrinfo)(res);
            break;
    }
}

MOCK_FUNC_VAR_NEW(socket);
int MOCK_FUNC_WRAP(socket)(int domain, int type, int protocol) {
    int result;

    switch (MOCK_GET_TYPE(socket)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(socket)(domain, type, protocol);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(domain);
            check_expected(type);
            check_expected(protocol);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(socket)(domain, type, protocol);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(setsockopt);
int MOCK_FUNC_WRAP(setsockopt)(int fd, int level, int optname, const void *optval, socklen_t optlen) {
    int result;

    switch (MOCK_GET_TYPE(setsockopt)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(setsockopt)(fd, level, optname, optval, optlen);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(fd);
            check_expected(level);
            check_expected(optname);
            check_expected_ptr(optval);
            check_expected(optlen);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(setsockopt)(fd, level, optname, optval, optlen);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(accept);
int MOCK_FUNC_WRAP(accept_errno = 0);
int MOCK_FUNC_WRAP(accept)(int fd, __SOCKADDR_ARG addr, socklen_t *len) {
    int result;

    switch (MOCK_GET_TYPE(accept)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(accept)(fd, addr, len);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(fd);
            check_expected_ptr(addr);
            check_expected(len);
            if (MOCK_FUNC_WRAP(accept_errno) != 0) {
                errno = MOCK_FUNC_WRAP(accept_errno);
                MOCK_FUNC_WRAP(accept_errno) = 0;
            }
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(accept)(fd, addr, len);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(connect);
int MOCK_FUNC_WRAP(connect)(int fd, const struct sockaddr *addr, socklen_t len) {
    int result;

    switch (MOCK_GET_TYPE(connect)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(connect)(fd, addr, len);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(fd);
            check_expected_ptr(addr);
            check_expected(len);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(connect)(fd, addr, len);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(bind);
int MOCK_FUNC_WRAP(bind)(int fd, __CONST_SOCKADDR_ARG addr, socklen_t len) {
    int result;

    switch (MOCK_GET_TYPE(bind)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(bind)(fd, addr, len);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(fd);
            check_expected(addr);
            check_expected(len);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(bind)(fd, addr, len);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(listen);
int MOCK_FUNC_WRAP(listen)(int fd, int n) {
    int result;

    switch (MOCK_GET_TYPE(listen)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(listen)(fd, n);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(fd);
            check_expected(n);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(listen)(fd, n);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(close);
int MOCK_FUNC_WRAP(close)(int fd) {
    int result;

    switch (MOCK_GET_TYPE(close)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(close)(fd);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(fd);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(close)(fd);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(open);
int MOCK_FUNC_WRAP(open)(char *file, int flags, mode_t mode) {
    int result;

    switch (MOCK_GET_TYPE(open)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(open)(file, flags, mode);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(file);
            check_expected(flags);
            check_expected(mode);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(open)(file, flags, mode);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(pselect);
int MOCK_FUNC_WRAP(pselect_errno = 0);
int MOCK_FUNC_WRAP(pselect)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                            const struct timespec *timeout, const __sigset_t *sigmask) {
    int result;

    switch (MOCK_GET_TYPE(pselect)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(pselect)(nfds, readfds, writefds, exceptfds, timeout, sigmask);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(nfds);
            check_expected_ptr(readfds);
            check_expected_ptr(writefds);
            check_expected_ptr(exceptfds);
            check_expected_ptr(timeout);
            check_expected_ptr(sigmask);
            if (MOCK_FUNC_WRAP(pselect_errno) != 0) {
                errno = MOCK_FUNC_WRAP(pselect_errno);
                MOCK_FUNC_WRAP(pselect_errno) = 0;
            }
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(pselect)(nfds, readfds, writefds, exceptfds, timeout, sigmask);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(raise);
int MOCK_FUNC_WRAP(raise)(int __sig) {
    int result;

    switch (MOCK_GET_TYPE(raise)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(raise)(__sig);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(__sig);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(raise)(__sig);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(pthread_create);
int MOCK_FUNC_WRAP(pthread_create)(pthread_t *__newthread, const pthread_attr_t *__attr,
                                   void *(*__start_routine)(void *), void *__arg) {
    int result;

    switch (MOCK_GET_TYPE(pthread_create)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(pthread_create)(__newthread, __attr, __start_routine, __arg);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(__newthread);
            check_expected_ptr(__attr);
            check_expected_ptr(__start_routine);
            check_expected_ptr(__arg);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(pthread_create)(__newthread, __attr, __start_routine, __arg);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(pthread_once);
int MOCK_FUNC_WRAP(pthread_once)(pthread_once_t *__once_control, void (*__init_routine)(void)) {
    int result;

    switch (MOCK_GET_TYPE(pthread_once)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(pthread_once)(__once_control, __init_routine);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(__once_control);
            check_expected_ptr(__init_routine);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(pthread_once)(__once_control, __init_routine);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(pthread_join);
int MOCK_FUNC_WRAP(pthread_join)(pthread_t __th, void **__thread_return) {
    int result;

    switch (MOCK_GET_TYPE(pthread_join)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(pthread_join)(__th, __thread_return);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(__th);
            check_expected_ptr(__thread_return);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(pthread_join)(__th, __thread_return);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(pthread_mutex_init);
int MOCK_FUNC_WRAP(pthread_mutex_init)(pthread_mutex_t *__mutex, const pthread_mutexattr_t *__mutexattr) {
    int result;

    switch (MOCK_GET_TYPE(pthread_mutex_init)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(pthread_mutex_init)(__mutex, __mutexattr);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(__mutex);
            check_expected_ptr(__mutexattr);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(pthread_mutex_init)(__mutex, __mutexattr);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(pthread_mutex_destroy);
int MOCK_FUNC_WRAP(pthread_mutex_destroy)(pthread_mutex_t *__mutex) {
    int result;

    switch (MOCK_GET_TYPE(pthread_mutex_destroy)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(pthread_mutex_destroy)(__mutex);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(__mutex);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(pthread_mutex_destroy)(__mutex);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(pthread_mutex_trylock);
int MOCK_FUNC_WRAP(pthread_mutex_trylock)(pthread_mutex_t *__mutex) {
    int result;

    switch (MOCK_GET_TYPE(pthread_mutex_trylock)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(pthread_mutex_trylock)(__mutex);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(__mutex);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(pthread_mutex_trylock)(__mutex);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(pthread_mutex_lock);
int MOCK_FUNC_WRAP(pthread_mutex_lock)(pthread_mutex_t *__mutex) {
    int result;

    switch (MOCK_GET_TYPE(pthread_mutex_lock)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(pthread_mutex_lock)(__mutex);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(__mutex);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(pthread_mutex_lock)(__mutex);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(pthread_mutex_unlock);
int MOCK_FUNC_WRAP(pthread_mutex_unlock)(pthread_mutex_t *__mutex) {
    int result;

    switch (MOCK_GET_TYPE(pthread_mutex_unlock)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(pthread_mutex_unlock)(__mutex);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(__mutex);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(pthread_mutex_unlock)(__mutex);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(pthread_mutex_timedlock);
int MOCK_FUNC_WRAP(pthread_mutex_timedlock)(pthread_mutex_t *__mutex, const struct timespec *__abstime) {
    int result;

    switch (MOCK_GET_TYPE(pthread_mutex_timedlock)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(pthread_mutex_timedlock)(__mutex, __abstime);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(__mutex);
            check_expected_ptr(__abstime);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(pthread_mutex_timedlock)(__mutex, __abstime);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(pthread_setname_np);
int MOCK_FUNC_WRAP(pthread_setname_np)(pthread_t thread, const char *name) {
    int result;

    switch (MOCK_GET_TYPE(pthread_setname_np)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(pthread_setname_np)(thread, name);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(thread);
            check_expected_ptr(name);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(pthread_setname_np)(thread, name);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(sem_init);
int MOCK_FUNC_WRAP(sem_init)(sem_t *__sem, int __pshared, unsigned int __value) {
    int result;

    switch (MOCK_GET_TYPE(sem_init)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(sem_init)(__sem, __pshared, __value);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(__sem);
            check_expected(__pshared);
            check_expected(__value);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(sem_init)(__sem, __pshared, __value);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(sem_post);
int MOCK_FUNC_WRAP(sem_post)(sem_t *__sem) {
    int result;

    switch (MOCK_GET_TYPE(sem_post)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(sem_post)(__sem);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(__sem);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(sem_post)(__sem);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(sem_destroy);
int MOCK_FUNC_WRAP(sem_destroy)(sem_t *__sem) {
    int result;

    switch (MOCK_GET_TYPE(sem_destroy)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(sem_destroy)(__sem);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(__sem);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(sem_destroy)(__sem);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(sem_timedwait);
int MOCK_FUNC_WRAP(sem_timedwait)(sem_t *__sem, const struct timespec *__abstime) {
    int result;

    switch (MOCK_GET_TYPE(sem_timedwait)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(sem_timedwait)(__sem, __abstime);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected_ptr(__sem);
            check_expected_ptr(__abstime);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(sem_timedwait)(__sem, __abstime);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(eventfd);
int MOCK_FUNC_WRAP(eventfd)(unsigned int __count, int __flags) {
    int result;

    switch (MOCK_GET_TYPE(eventfd)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(eventfd)(__count, __flags);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(__count);
            check_expected(__flags);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(eventfd)(__count, __flags);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(eventfd_read);
int MOCK_FUNC_WRAP(eventfd_read)(int __fd, eventfd_t *__value) {
    int result;

    switch (MOCK_GET_TYPE(eventfd_read)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(eventfd_read)(__fd, __value);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(__fd);
            check_expected_ptr(__value);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(eventfd_read)(__fd, __value);
            break;
    }

    return result;
}

MOCK_FUNC_VAR_NEW(eventfd_write);
int MOCK_FUNC_WRAP(eventfd_write)(int __fd, eventfd_t __value) {
    int result;

    switch (MOCK_GET_TYPE(eventfd_write)) {
        case CMOCKA_MOCK_ENABLED_WITH_FUNC:
            result = MOCK_FUNC_WITH(eventfd_write)(__fd, __value);
            break;
        case CMOCKA_MOCK_ENABLED:
            check_expected(__fd);
            check_expected(__value);
            result = mock_type(int);
            break;
        default:
            result = MOCK_FUNC_REAL(eventfd_write)(__fd, __value);
            break;
    }

    return result;
}
