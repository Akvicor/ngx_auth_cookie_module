/*
 * ngx_http_auth_cookie_module — htpasswd 用户表
 *
 * 配置阶段读入用户名与密码哈希;文件修改在 reload 或重启后生效。
 * 支持 $apr1$ 与 $2a$/$2b$/$2y$。
 */

#ifndef _NGX_HTTP_AUTH_COOKIE_HTPASSWD_H_INCLUDED_
#define _NGX_HTTP_AUTH_COOKIE_HTPASSWD_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_auth_cookie_crypto.h"

#define NGX_AUTH_COOKIE_USER_FILE_MAX  (1024 * 1024)

typedef struct {
    ngx_str_t  name;
    ngx_str_t  hash;
    u_char     fingerprint[NGX_AUTH_COOKIE_HMAC_SHA256_LEN];
} ngx_http_auth_cookie_user_t;

/* 从用户文件载入内存表。结果使用传入 pool 的生命周期。 */
ngx_int_t ngx_http_auth_cookie_load_users(ngx_pool_t *pool, ngx_log_t *log,
    ngx_str_t *user_file, ngx_array_t **users);

/* 按用户名查找表项;未找到返回 NULL。 */
ngx_http_auth_cookie_user_t *ngx_http_auth_cookie_find_user(ngx_array_t *users,
    ngx_str_t *name);

/*
 * 校验用户与密码。
 * 返回 NGX_OK 通过;NGX_DECLINED 用户不存在或密码错误;
 * NGX_HTTP_* 为内部错误。
 */
ngx_int_t ngx_http_auth_cookie_check_user(ngx_http_request_t *r,
    ngx_array_t *users, ngx_str_t *user, ngx_str_t *passwd);

#endif /* _NGX_HTTP_AUTH_COOKIE_HTPASSWD_H_INCLUDED_ */
