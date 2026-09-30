/* 配置文件快照的载入与路径索引。 */
#include "ngx_http_auth_cookie_file_cache.h"
#include "ngx_http_auth_cookie_page.h"

/* 文件用途决定读取和校验方式，同一路径按用途独立缓存。 */
enum {
    NGX_AUTH_COOKIE_FILE_SECRET,
    NGX_AUTH_COOKIE_FILE_USERS,
    NGX_AUTH_COOKIE_FILE_PAGE
};

typedef struct {
    ngx_str_node_t                 node;
    ngx_str_t                      content;
    ngx_http_auth_cookie_users_t   *users;
} ngx_http_auth_cookie_file_t;

void
ngx_http_auth_cookie_file_cache_init(ngx_http_auth_cookie_file_cache_t *cache)
{
    ngx_uint_t i;

    for (i = 0; i < 3; i++) {
        ngx_rbtree_init(&cache->trees[i], &cache->sentinels[i],
                       ngx_str_rbtree_insert_value);
    }
}

static ngx_http_auth_cookie_file_t *
ngx_http_auth_cookie_file_get(ngx_conf_t *cf,
    ngx_http_auth_cookie_file_cache_t *cache, ngx_str_t *path, ngx_uint_t type)
{
    ngx_http_auth_cookie_file_t *file;
    ngx_int_t                   rc;
    uint32_t                    hash;

    hash = ngx_crc32_short(path->data, path->len);
    file = (ngx_http_auth_cookie_file_t *)
           ngx_str_rbtree_lookup(&cache->trees[type], path, hash);
    if (file != NULL) {
        return file;
    }

    file = ngx_pcalloc(cf->pool, sizeof(*file));
    if (file == NULL) {
        return NULL;
    }
    file->node.str = *path;
    file->node.node.key = hash;

    switch (type) {
    case NGX_AUTH_COOKIE_FILE_SECRET:
        rc = ngx_http_auth_cookie_load_secret(cf->pool, cf->log, path,
                                             &file->content);
        break;
    case NGX_AUTH_COOKIE_FILE_USERS:
        rc = ngx_http_auth_cookie_load_users(cf->pool, cf->log, path,
                                            &file->users);
        break;
    default:
        rc = ngx_http_auth_cookie_load_page(cf->pool, cf->log, path,
                                           &file->content);
        break;
    }
    if (rc != NGX_OK) {
        return NULL;
    }

    ngx_rbtree_insert(&cache->trees[type], &file->node.node);
    return file;
}

ngx_int_t
ngx_http_auth_cookie_file_cache_load(ngx_conf_t *cf,
    ngx_http_auth_cookie_file_cache_t *cache, ngx_str_t *secret_path,
    ngx_str_t *user_path, ngx_str_t *page_path, ngx_str_t *secret,
    ngx_http_auth_cookie_users_t **users, ngx_str_t *page)
{
    ngx_http_auth_cookie_file_t *file;

    file = ngx_http_auth_cookie_file_get(cf, cache, secret_path,
                                        NGX_AUTH_COOKIE_FILE_SECRET);
    if (file == NULL) {
        return NGX_ERROR;
    }
    *secret = file->content;

    file = ngx_http_auth_cookie_file_get(cf, cache, user_path,
                                        NGX_AUTH_COOKIE_FILE_USERS);
    if (file == NULL) {
        return NGX_ERROR;
    }
    *users = file->users;

    if (page_path->len > 1 && page_path->data[0] == '/') {
        file = ngx_http_auth_cookie_file_get(cf, cache, page_path,
                                            NGX_AUTH_COOKIE_FILE_PAGE);
        if (file == NULL) {
            return NGX_ERROR;
        }
        *page = file->content;
    }
    return NGX_OK;
}
