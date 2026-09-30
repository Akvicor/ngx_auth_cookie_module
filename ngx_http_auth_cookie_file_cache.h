/* 配置周期内的文件快照缓存，按文件用途及原始路径区分。 */
#ifndef _NGX_HTTP_AUTH_COOKIE_FILE_CACHE_H_INCLUDED_
#define _NGX_HTTP_AUTH_COOKIE_FILE_CACHE_H_INCLUDED_

#include "ngx_http_auth_cookie_htpasswd.h"

/* 三类文件各自索引，避免同一路径的不同用途混用解析结果。 */
typedef struct {
    ngx_rbtree_t       trees[3];
    ngx_rbtree_node_t  sentinels[3];
} ngx_http_auth_cookie_file_cache_t;

/* 初始化配置池持有的缓存；reload 创建新的缓存。 */
void ngx_http_auth_cookie_file_cache_init(ngx_http_auth_cookie_file_cache_t *cache);

/* 载入认证配置引用的文件；各路径仅在首次引用时读取。 */
ngx_int_t ngx_http_auth_cookie_file_cache_load(ngx_conf_t *cf,
    ngx_http_auth_cookie_file_cache_t *cache, ngx_str_t *secret_path,
    ngx_str_t *user_path, ngx_str_t *page_path, ngx_str_t *secret,
    ngx_http_auth_cookie_users_t **users, ngx_str_t *page);

#endif
