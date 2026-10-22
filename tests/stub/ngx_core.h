/*
 * 单元测试桩:ngx_core.h 的最小替代。
 * 用 malloc 模拟请求池,用系统调用实现文件接口,使正式的
 * crypto.c / util.c 可以脱离 nginx 编译并测试真实代码路径。
 */

#ifndef TEST_NGX_CORE_H
#define TEST_NGX_CORE_H

#include <ngx_config.h>

typedef intptr_t   ngx_int_t;
typedef uintptr_t  ngx_uint_t;
typedef int        ngx_err_t;
typedef int        ngx_flag_t;
typedef int        ngx_fd_t;
typedef unsigned char u_char;

typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;

typedef struct {
    int unused;
} ngx_log_t;

typedef struct stat ngx_file_info_t;

typedef struct {
    ngx_fd_t    fd;
    ngx_str_t   name;
    ngx_log_t  *log;
} ngx_file_t;

typedef struct ngx_pool_s {
    int unused;
} ngx_pool_t;

#define NGX_OK        0
#define NGX_ERROR    -1
#define NGX_DECLINED -2

#define ngx_string(s)     { sizeof(s) - 1, (u_char *) s }
#define ngx_null_string   { 0, NULL }
#define ngx_str_set(str, text)                                                \
    (str)->len = sizeof(text) - 1; (str)->data = (u_char *) text
#define ngx_str_null(str)   (str)->len = 0; (str)->data = NULL

#define ngx_memzero(buf, n)  (void) memset(buf, 0, n)
#define ngx_memcpy(dst, src, n)  (void) memcpy(dst, src, n)
#define ngx_cpymem(dst, src, n)  (((u_char *) memcpy(dst, src, n)) + (n))
#define ngx_strncmp(s1, s2, n)   strncmp((const char *) (s1), (const char *) (s2), n)
#define ngx_strncasecmp(s1, s2, n)                                          \
    strncasecmp((const char *) (s1), (const char *) (s2), n)
#define ngx_strlchr(p, last, c)  ((u_char *) memchr((p), (c), (last) - (p)))

#define ngx_errno        errno
#define NGX_ENOENT       ENOENT
#define NGX_EEXIST       EEXIST

#define NGX_INVALID_FILE  (-1)
#define NGX_FILE_ERROR    (-1)

#define NGX_FILE_RDONLY          O_RDONLY
#define NGX_FILE_WRONLY          O_WRONLY
#define NGX_FILE_NONBLOCK        O_NONBLOCK
#define NGX_FILE_OPEN            0
#define NGX_FILE_CREATE_OR_OPEN  O_CREAT
#define NGX_FILE_TRUNCATE        O_TRUNC
#define NGX_FILE_OWNER_ACCESS    0600

#define NGX_LOG_EMERG  0
#define NGX_LOG_ERR    4

#define ngx_open_file(name, mode, create, access)                           \
    open((const char *) (name), (mode) | (create), (access))
#define ngx_close_file   close
#define ngx_delete_file(name)  unlink((const char *) (name))
#define ngx_fd_info(fd, fi)      fstat((fd), (fi))
#define ngx_is_file(fi)          S_ISREG((fi)->st_mode)
#define ngx_file_access(fi)      ((fi)->st_mode & 0777)
#define ngx_file_size(fi)        ((fi)->st_size)
#define ngx_read_file(file, buf, size, offset)                              \
    pread((file)->fd, (buf), (size), (offset))
#define ngx_write_fd(fd, buf, n)  write((fd), (buf), (n))

static inline void
ngx_explicit_memzero(void *buf, size_t n)
{
    volatile u_char  *p = buf;

    while (n--) {
        *p++ = 0;
    }
}

static inline void *
ngx_palloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    return malloc(size);
}

static inline void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    return malloc(size);
}

static inline void *
ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    return calloc(1, size);
}

#define ngx_time()  time(NULL)

u_char *ngx_sprintf(u_char *buf, const char *fmt, ...);
ngx_int_t ngx_atoi(u_char *line, size_t n);
void ngx_log_error(int level, ngx_log_t *log, int err, const char *fmt, ...);

#endif
