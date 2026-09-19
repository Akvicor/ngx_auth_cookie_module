/*
 * ngx_http_auth_cookie_module — 登录 POST 限流
 *
 * 令牌桶状态保存在模块级共享内存中，按认证域、客户端 IP 和可选用户名生成固定
 * 长度摘要。所有速率计算使用整数毫令牌，不使用浮点。
 */

#ifndef _NGX_HTTP_AUTH_COOKIE_RATE_LIMIT_H_INCLUDED_
#define _NGX_HTTP_AUTH_COOKIE_RATE_LIMIT_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_AUTH_COOKIE_RATE_KEY_LEN          32
#define NGX_AUTH_COOKIE_RATE_KEY_IP           0
#define NGX_AUTH_COOKIE_RATE_KEY_USERNAME     1
#define NGX_AUTH_COOKIE_RATE_KEY_IP_USERNAME  2

#define NGX_AUTH_COOKIE_RATE_ALLOWED          NGX_OK
#define NGX_AUTH_COOKIE_RATE_DENIED           NGX_DECLINED
#define NGX_AUTH_COOKIE_RATE_BAD_IP           NGX_DONE

/* 两级令牌桶参数；loc conf 中的指针为 NULL 时表示显式关闭限流。 */
typedef struct {
    ngx_uint_t   capacity;
    ngx_msec_t   period;
} ngx_http_auth_cookie_rate_bucket_conf_t;

typedef struct {
    ngx_http_auth_cookie_rate_bucket_conf_t  ip;
    ngx_http_auth_cookie_rate_bucket_conf_t  username;
} ngx_http_auth_cookie_rate_conf_t;

typedef struct {
    ngx_str_t    name;
    ngx_uint_t   hash;
} ngx_http_auth_cookie_rate_header_t;

typedef struct {
    ngx_http_auth_cookie_rate_conf_t  *rate;
    ngx_uint_t                         key_mode;
    ngx_array_t                       *ip_headers;
    ngx_array_t                       *trusted_proxies;
    ngx_flag_t                         ip_headers_set;
    ngx_flag_t                         trusted_proxies_set;
    u_char                             scope[NGX_AUTH_COOKIE_RATE_KEY_LEN];
    ngx_flag_t                         scope_ready;
} ngx_http_auth_cookie_rate_loc_conf_t;

typedef struct {
    ngx_shm_zone_t  *ip_zone;
    ngx_shm_zone_t  *username_zone;
    size_t           zone_size;
    ngx_flag_t       auth_used;
} ngx_http_auth_cookie_rate_main_conf_t;

extern ngx_module_t ngx_http_auth_cookie_module;

char *ngx_http_auth_cookie_login_rate_set(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
char *ngx_http_auth_cookie_login_rate_key_set(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
char *ngx_http_auth_cookie_login_rate_ip_header_set(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
char *ngx_http_auth_cookie_login_rate_trusted_proxy_set(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
char *ngx_http_auth_cookie_login_rate_zone_size_set(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

void ngx_http_auth_cookie_rate_create_loc_conf(
    ngx_http_auth_cookie_rate_loc_conf_t *conf);
char *ngx_http_auth_cookie_rate_merge_loc_conf(ngx_conf_t *cf,
    ngx_http_auth_cookie_rate_loc_conf_t *prev,
    ngx_http_auth_cookie_rate_loc_conf_t *conf);

/* 由稳定配置内容生成认证域摘要；不包含容量和周期。 */
ngx_int_t ngx_http_auth_cookie_rate_scope(ngx_pool_t *pool, ngx_str_t *parts,
    ngx_uint_t count, u_char *out);

ngx_int_t ngx_http_auth_cookie_rate_zone_create(ngx_conf_t *cf,
    ngx_http_auth_cookie_rate_main_conf_t *conf);
ngx_int_t ngx_http_auth_cookie_rate_zone_init(ngx_shm_zone_t *zone,
    void *data);

/* username 为 NULL 时按 IP 键检查；返回值使用上方 NGX_AUTH_COOKIE_RATE_* 常量。 */
ngx_int_t ngx_http_auth_cookie_rate_check(ngx_http_request_t *r,
    ngx_http_auth_cookie_rate_loc_conf_t *conf, ngx_str_t *username);

#endif /* _NGX_HTTP_AUTH_COOKIE_RATE_LIMIT_H_INCLUDED_ */
