/*
 * ngx_http_auth_cookie_module — 登录 POST 限流实现
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/evp.h>

#include "ngx_http_auth_cookie_rate_limit.h"
#include "ngx_http_auth_cookie_module.h"

#define NGX_AUTH_COOKIE_RATE_DEFAULT_ZONE_SIZE  (1024 * 1024)
#define NGX_AUTH_COOKIE_RATE_MIN_ZONE_SIZE      (8 * ngx_pagesize)
#define NGX_AUTH_COOKIE_RATE_MAX_CAPACITY       1000000
#define NGX_AUTH_COOKIE_RATE_MAX_PERIOD         (7 * 24 * 60 * 60 * 1000)
#define NGX_AUTH_COOKIE_RATE_TOKEN_SCALE        1000

static ngx_http_auth_cookie_rate_conf_t ngx_http_auth_cookie_rate_default = {
    { 10, 1000 },
    { 1, 1000 }
};

typedef struct {
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel;
    ngx_queue_t        queue;
} ngx_http_auth_cookie_rate_shctx_t;

typedef struct {
    ngx_slab_pool_t                    *shpool;
    ngx_http_auth_cookie_rate_shctx_t  *sh;
} ngx_http_auth_cookie_rate_zone_ctx_t;

typedef struct {
    ngx_rbtree_node_t  node;
    ngx_queue_t        queue;
    uint64_t           tokens;
    ngx_msec_t         last;
    u_char             key[NGX_AUTH_COOKIE_RATE_KEY_LEN];
} ngx_http_auth_cookie_rate_node_t;


static ngx_int_t ngx_http_auth_cookie_rate_header_valid(ngx_str_t *name);
static ngx_table_elt_t *ngx_http_auth_cookie_rate_header(
    ngx_http_request_t *r, ngx_http_auth_cookie_rate_header_t *name,
    ngx_uint_t *count);
static ngx_int_t ngx_http_auth_cookie_rate_parse_ip(ngx_http_request_t *r,
    ngx_str_t *value, ngx_addr_t *addr);
static ngx_int_t ngx_http_auth_cookie_rate_source(ngx_http_request_t *r,
    ngx_http_auth_cookie_rate_loc_conf_t *conf, ngx_addr_t *addr);
static ngx_int_t ngx_http_auth_cookie_rate_key(ngx_http_request_t *r,
    ngx_http_auth_cookie_rate_loc_conf_t *conf, ngx_addr_t *addr,
    ngx_str_t *username, u_char *out);
static void ngx_http_auth_cookie_rate_expire(ngx_slab_pool_t *shpool,
    ngx_http_auth_cookie_rate_shctx_t *sh);


static uint32_t
ngx_http_auth_cookie_rate_hash(u_char *data, size_t len)
{
    return ngx_crc32_short(data, len);
}


/* 稳定配置内容经 SHA-256 形成认证域摘要，长度前缀避免字段拼接歧义。 */
ngx_int_t
ngx_http_auth_cookie_rate_scope(ngx_pool_t *pool, ngx_str_t *parts,
    ngx_uint_t count, u_char *out)
{
    u_char      *message, *p;
    size_t       len;
    uint32_t     part_len;
    unsigned int out_len;
    ngx_uint_t   i;

    len = 0;
    for (i = 0; i < count; i++) {
        if (parts[i].len > UINT32_MAX || len > NGX_MAX_SIZE_T_VALUE - 4
            || len + 4 > NGX_MAX_SIZE_T_VALUE - parts[i].len)
        {
            return NGX_ERROR;
        }
        len += 4 + parts[i].len;
    }

    message = ngx_pnalloc(pool, len);
    if (message == NULL) {
        return NGX_ERROR;
    }

    p = message;
    for (i = 0; i < count; i++) {
        part_len = (uint32_t) parts[i].len;
        p = ngx_cpymem(p, &part_len, 4);
        p = ngx_cpymem(p, parts[i].data, parts[i].len);
    }

    out_len = NGX_AUTH_COOKIE_RATE_KEY_LEN;
    if (EVP_Digest(message, len, out, &out_len, EVP_sha256(), NULL) != 1
        || out_len != NGX_AUTH_COOKIE_RATE_KEY_LEN)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


char *
ngx_http_auth_cookie_login_rate_set(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_auth_cookie_rate_loc_conf_t  *rlcf = (void *)
        ((char *) conf + cmd->offset);
    ngx_http_auth_cookie_rate_conf_t      *rate;
    ngx_str_t                             *value;
    ngx_int_t                              ip_capacity, username_capacity;
    ngx_msec_int_t                         ip_period, username_period;

    if (rlcf->rate != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2 && value[1].len == 3
        && ngx_strncmp(value[1].data, "off", 3) == 0)
    {
        rlcf->rate = NULL;
        return NGX_CONF_OK;
    }

    if (cf->args->nelts != 5) {
        return "requires ip capacity/period and ip+username capacity/period or off";
    }

    ip_capacity = ngx_atoi(value[1].data, value[1].len);
    ip_period = ngx_parse_time(&value[2], 0);
    username_capacity = ngx_atoi(value[3].data, value[3].len);
    username_period = ngx_parse_time(&value[4], 0);
    if (ip_capacity <= 0 || ip_capacity > NGX_AUTH_COOKIE_RATE_MAX_CAPACITY
        || ip_period <= 0 || ip_period > NGX_AUTH_COOKIE_RATE_MAX_PERIOD
        || username_capacity <= 0
        || username_capacity > NGX_AUTH_COOKIE_RATE_MAX_CAPACITY
        || username_period <= 0
        || username_period > NGX_AUTH_COOKIE_RATE_MAX_PERIOD)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid auth_cookie_login_rate \"%V %V %V %V\"",
                           &value[1], &value[2], &value[3], &value[4]);
        return NGX_CONF_ERROR;
    }

    rate = ngx_pcalloc(cf->pool, sizeof(*rate));
    if (rate == NULL) {
        return NGX_CONF_ERROR;
    }
    rate->ip.capacity = (ngx_uint_t) ip_capacity;
    rate->ip.period = (ngx_msec_t) ip_period;
    rate->username.capacity = (ngx_uint_t) username_capacity;
    rate->username.period = (ngx_msec_t) username_period;
    rlcf->rate = rate;

    return NGX_CONF_OK;
}


char *
ngx_http_auth_cookie_login_rate_key_set(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_auth_cookie_rate_loc_conf_t  *rlcf = (void *)
        ((char *) conf + cmd->offset);
    ngx_str_t                             *value;

    if (rlcf->key_mode != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;
    if (value[1].len == 2 && ngx_strncmp(value[1].data, "ip", 2) == 0) {
        rlcf->key_mode = NGX_AUTH_COOKIE_RATE_KEY_IP;
    } else if (value[1].len == sizeof("username") - 1
               && ngx_strncmp(value[1].data, "username",
                              sizeof("username") - 1) == 0)
    {
        rlcf->key_mode = NGX_AUTH_COOKIE_RATE_KEY_USERNAME;
    } else if (value[1].len == sizeof("ip_username") - 1
               && ngx_strncmp(value[1].data, "ip_username",
                              sizeof("ip_username") - 1) == 0)
    {
        rlcf->key_mode = NGX_AUTH_COOKIE_RATE_KEY_IP_USERNAME;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid auth_cookie_login_rate_key \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/* 列表指令支持一行多个值和多行追加；off 只能单独出现。 */
static char *
ngx_http_auth_cookie_rate_list_set(ngx_conf_t *cf, ngx_array_t **list,
    ngx_flag_t *configured, size_t size, ngx_uint_t proxies)
{
    ngx_str_t     *value;
    void          *item;
    ngx_uint_t     i;
    ngx_cidr_t     cidr, *entry;
    ngx_http_auth_cookie_rate_header_t *header;
    ngx_int_t      rc;

    value = cf->args->elts;

    if (cf->args->nelts == 2 && value[1].len == 3
        && ngx_strncmp(value[1].data, "off", 3) == 0)
    {
        if (*configured == 1) {
            return "off cannot be combined with an existing list";
        }
        *list = ngx_array_create(cf->pool, 1, size);
        if (*list == NULL) {
            return NGX_CONF_ERROR;
        }
        *configured = -1;
        return NGX_CONF_OK;
    }

    if (*configured == -1) {
        return "values cannot follow off";
    }

    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len == 3 && ngx_strncmp(value[i].data, "off", 3) == 0) {
            return "off cannot be combined with values";
        }
    }

    if (*configured == 0) {
        *list = ngx_array_create(cf->pool, cf->args->nelts - 1, size);
        if (*list == NULL) {
            return NGX_CONF_ERROR;
        }
        *configured = 1;
    }

    for (i = 1; i < cf->args->nelts; i++) {
        item = ngx_array_push(*list);
        if (item == NULL) {
            return NGX_CONF_ERROR;
        }

        if (proxies) {
#if (NGX_HAVE_UNIX_DOMAIN)
            /* 与 realip 的 unix: 写法一致，表示信任本机 unix socket 来源。 */
            if (value[i].len == sizeof("unix:") - 1
                && ngx_strncmp(value[i].data, "unix:", sizeof("unix:") - 1) == 0)
            {
                entry = item;
                ngx_memzero(entry, sizeof(*entry));
                entry->family = AF_UNIX;
                continue;
            }
#endif
            rc = ngx_ptocidr(&value[i], &cidr);
            if (rc == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid trusted proxy \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }
            if (rc == NGX_DONE) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "trusted proxy \"%V\" has low bits set",
                                   &value[i]);
            }
            entry = item;
            *entry = cidr;
        } else {
            if (!ngx_http_auth_cookie_rate_header_valid(&value[i])) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid IP header \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }
            header = item;
            header->name.len = value[i].len;
            header->name.data = ngx_pnalloc(cf->pool, value[i].len + 1);
            if (header->name.data == NULL) {
                return NGX_CONF_ERROR;
            }
            header->hash = ngx_hash_strlow(header->name.data, value[i].data,
                                           value[i].len);
            header->name.data[value[i].len] = '\0';
        }
    }

    return NGX_CONF_OK;
}


char *
ngx_http_auth_cookie_login_rate_ip_header_set(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_cookie_rate_loc_conf_t *rlcf = (void *)
        ((char *) conf + cmd->offset);

    return ngx_http_auth_cookie_rate_list_set(cf, &rlcf->ip_headers,
        &rlcf->ip_headers_set, sizeof(ngx_http_auth_cookie_rate_header_t), 0);
}


char *
ngx_http_auth_cookie_login_rate_trusted_proxy_set(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_cookie_rate_loc_conf_t *rlcf = (void *)
        ((char *) conf + cmd->offset);

    return ngx_http_auth_cookie_rate_list_set(cf, &rlcf->trusted_proxies,
        &rlcf->trusted_proxies_set, sizeof(ngx_cidr_t), 1);
}


char *
ngx_http_auth_cookie_login_rate_zone_size_set(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_cookie_rate_main_conf_t  *amcf = (void *)
        ((char *) conf + cmd->offset);
    ngx_str_t                              *value;
    ssize_t                                 size;

    if (amcf->zone_size != NGX_CONF_UNSET_SIZE) {
        return "is duplicate";
    }

    value = cf->args->elts;
    size = ngx_parse_size(&value[1]);
    if (size == NGX_ERROR || (size_t) size < NGX_AUTH_COOKIE_RATE_MIN_ZONE_SIZE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid auth_cookie_login_rate_zone_size \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    amcf->zone_size = (size_t) size;
    return NGX_CONF_OK;
}


void
ngx_http_auth_cookie_rate_create_loc_conf(
    ngx_http_auth_cookie_rate_loc_conf_t *conf)
{
    conf->rate = NGX_CONF_UNSET_PTR;
    conf->key_mode = NGX_CONF_UNSET_UINT;
    conf->ip_headers = NGX_CONF_UNSET_PTR;
    conf->trusted_proxies = NGX_CONF_UNSET_PTR;
    conf->ip_headers_set = 0;
    conf->trusted_proxies_set = 0;
    conf->scope_ready = 0;
}


char *
ngx_http_auth_cookie_rate_merge_loc_conf(ngx_conf_t *cf,
    ngx_http_auth_cookie_rate_loc_conf_t *prev,
    ngx_http_auth_cookie_rate_loc_conf_t *conf)
{
    if (conf->rate == NGX_CONF_UNSET_PTR) {
        conf->rate = prev->rate;
    }
    if (conf->rate == NGX_CONF_UNSET_PTR) {
        conf->rate = &ngx_http_auth_cookie_rate_default;
    }

    ngx_conf_merge_uint_value(conf->key_mode, prev->key_mode,
                              NGX_AUTH_COOKIE_RATE_KEY_IP_USERNAME);

    if (conf->ip_headers == NGX_CONF_UNSET_PTR) {
        conf->ip_headers = prev->ip_headers;
    }
    if (conf->trusted_proxies == NGX_CONF_UNSET_PTR) {
        conf->trusted_proxies = prev->trusted_proxies;
    }
    if (conf->ip_headers == NGX_CONF_UNSET_PTR) {
        conf->ip_headers = NULL;
    }
    if (conf->trusted_proxies == NGX_CONF_UNSET_PTR) {
        conf->trusted_proxies = NULL;
    }

    if (conf->ip_headers != NULL && conf->ip_headers->nelts != 0
        && (conf->trusted_proxies == NULL || conf->trusted_proxies->nelts == 0))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_cookie_login_rate_ip_header requires "
                           "auth_cookie_login_rate_trusted_proxy");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_auth_cookie_rate_header_valid(ngx_str_t *name)
{
    size_t i;

    if (name->len == 0 || name->len > 128) {
        return 0;
    }
    for (i = 0; i < name->len; i++) {
        u_char c = name->data[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9') || c == '!' || c == '#'
            || c == '$' || c == '%' || c == '&' || c == '\''
            || c == '*' || c == '+' || c == '-' || c == '.'
            || c == '^' || c == '_' || c == '`' || c == '|'
            || c == '~')
        {
            continue;
        }
        return 0;
    }
    return 1;
}


static ngx_table_elt_t *
ngx_http_auth_cookie_rate_header(ngx_http_request_t *r,
    ngx_http_auth_cookie_rate_header_t *name, ngx_uint_t *count)
{
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header, *found;

    *count = 0;
    found = NULL;
    part = &r->headers_in.headers.part;
    header = part->elts;

    for ( ;; ) {
        for (ngx_uint_t i = 0; i < part->nelts; i++) {
            if (header[i].hash == name->hash
                && header[i].key.len == name->name.len
                && ngx_strncmp(header[i].lowcase_key, name->name.data,
                               name->name.len) == 0)
            {
                (*count)++;
                if (found == NULL) {
                    found = &header[i];
                }
            }
        }
        if (part->next == NULL) {
            break;
        }
        part = part->next;
        header = part->elts;
    }

    return found;
}


static ngx_int_t
ngx_http_auth_cookie_rate_parse_ip(ngx_http_request_t *r, ngx_str_t *value,
    ngx_addr_t *addr)
{
    u_char  *start, *end;

    start = value->data;
    end = value->data + value->len;
    while (start < end && (*start == ' ' || *start == '\t')) {
        start++;
    }
    while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
        end--;
    }
    if (start == end) {
        return NGX_DECLINED;
    }

    if (ngx_parse_addr(r->pool, addr, start, end - start) != NGX_OK) {
        return NGX_DECLINED;
    }
    if (addr->sockaddr->sa_family != AF_INET
#if (NGX_HAVE_INET6)
        && addr->sockaddr->sa_family != AF_INET6
#endif
        )
    {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


/* realip 已改写地址时优先使用其结果，并用原连接地址判断可信代理。 */
static ngx_addr_t *
ngx_http_auth_cookie_rate_direct_addr(ngx_http_request_t *r, ngx_addr_t *addr,
    ngx_uint_t *realip_done)
{
#if (NGX_HTTP_REALIP)
    static ngx_str_t  name = ngx_string("realip_remote_addr");
    ngx_http_variable_value_t *value;
    ngx_uint_t key = ngx_hash_key((u_char *) name.data, name.len);

    value = ngx_http_get_variable(r, &name, key);
    if (value != NULL && !value->not_found && value->len != 0
        && ngx_parse_addr(r->pool, addr, value->data, value->len) == NGX_OK)
    {
        *realip_done = 0;
        if (value->len != r->connection->addr_text.len
            || ngx_memcmp(value->data, r->connection->addr_text.data,
                          value->len) != 0)
        {
            *realip_done = 1;
        }
        return addr;
    }
#endif
    addr->sockaddr = r->connection->sockaddr;
    addr->socklen = r->connection->socklen;
    *realip_done = 0;
    return addr;
}


static ngx_int_t
ngx_http_auth_cookie_rate_header_addr(ngx_http_request_t *r,
    ngx_http_auth_cookie_rate_header_t *name, ngx_array_t *proxies,
    ngx_addr_t *direct, ngx_addr_t *addr)
{
    static const ngx_str_t xff = ngx_string("x-forwarded-for");
    ngx_table_elt_t *header;
    ngx_uint_t count;
    ngx_int_t rc;

    if (name->name.len == xff.len
        && ngx_strncmp(name->name.data, xff.data, xff.len) == 0)
    {
        if (r->headers_in.x_forwarded_for == NULL) {
            return NGX_DECLINED;
        }
        *addr = *direct;
        rc = ngx_http_get_forwarded_addr(r, addr,
                                         r->headers_in.x_forwarded_for, NULL,
                                         proxies, 1);
        return (rc == NGX_OK || rc == NGX_DONE) ? NGX_OK : NGX_DECLINED;
    }

    header = ngx_http_auth_cookie_rate_header(r, name, &count);
    if (count != 1 || header == NULL) {
        return NGX_DECLINED;
    }
    return ngx_http_auth_cookie_rate_parse_ip(r, &header->value, addr);
}


static ngx_int_t
ngx_http_auth_cookie_rate_source(ngx_http_request_t *r,
    ngx_http_auth_cookie_rate_loc_conf_t *conf, ngx_addr_t *addr)
{
    ngx_addr_t direct;
    ngx_uint_t realip_done, i;
    ngx_http_auth_cookie_rate_header_t *headers;
    ngx_int_t rc;

    (void) ngx_http_auth_cookie_rate_direct_addr(r, &direct, &realip_done);
    if (realip_done) {
        addr->sockaddr = r->connection->sockaddr;
        addr->socklen = r->connection->socklen;
        return NGX_OK;
    }

    if (conf->trusted_proxies == NULL || conf->trusted_proxies->nelts == 0) {
        rc = NGX_DECLINED;
    } else {
        rc = ngx_cidr_match(direct.sockaddr, conf->trusted_proxies);
    }
    if (rc != NGX_OK) {
        if (conf->ip_headers != NULL && conf->ip_headers->nelts != 0) {
            return NGX_DECLINED;
        }
        *addr = direct;
        return NGX_OK;
    }

    if (conf->ip_headers != NULL && conf->ip_headers->nelts != 0) {
        headers = conf->ip_headers->elts;
        for (i = 0; i < conf->ip_headers->nelts; i++) {
            rc = ngx_http_auth_cookie_rate_header_addr(r, &headers[i],
                                                     conf->trusted_proxies,
                                                     &direct, addr);
            if (rc == NGX_OK) {
                return NGX_OK;
            }
        }
        return NGX_DECLINED;
    }

    if (r->headers_in.x_forwarded_for != NULL) {
        *addr = direct;
        rc = ngx_http_get_forwarded_addr(r, addr,
                                         r->headers_in.x_forwarded_for, NULL,
                                         conf->trusted_proxies, 1);
        if (rc == NGX_OK || rc == NGX_DONE) {
            return NGX_OK;
        }
    }

    if (r->headers_in.x_real_ip != NULL) {
        rc = ngx_http_auth_cookie_rate_parse_ip(r,
            &r->headers_in.x_real_ip->value, addr);
        if (rc == NGX_OK) {
            return NGX_OK;
        }
    }

    *addr = direct;
    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_cookie_rate_key(ngx_http_request_t *r,
    ngx_http_auth_cookie_rate_loc_conf_t *conf, ngx_addr_t *addr,
    ngx_str_t *username, u_char *out)
{
    u_char       *message, *p, *address;
    size_t        len, addr_len;
    uint32_t      family, user_len;
    unsigned int  out_len;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    family = (uint32_t) addr->sockaddr->sa_family;
    switch (addr->sockaddr->sa_family) {
    case AF_INET:
        sin = (struct sockaddr_in *) addr->sockaddr;
        address = (u_char *) &sin->sin_addr;
        addr_len = 4;
        break;
#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) addr->sockaddr;
        address = sin6->sin6_addr.s6_addr;
        /* 映射地址归一，原生 IPv6 按 /64 聚合，限制同一来源轮换地址。 */
        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            family = AF_INET;
            address += 12;
            addr_len = 4;
        } else {
            addr_len = 8;
        }
        break;
#endif
    default:
        address = r->connection->addr_text.data;
        addr_len = r->connection->addr_text.len;
        break;
    }

    user_len = username == NULL ? 0 : (uint32_t) username->len;
    len = NGX_AUTH_COOKIE_RATE_KEY_LEN + 4 + addr_len + 4 + user_len;
    message = ngx_pnalloc(r->pool, len);
    if (message == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(message, conf->scope, NGX_AUTH_COOKIE_RATE_KEY_LEN);
    p = ngx_cpymem(p, &family, 4);
    p = ngx_cpymem(p, address, addr_len);

    p = ngx_cpymem(p, &user_len, 4);
    if (user_len != 0) {
        p = ngx_cpymem(p, username->data, username->len);
    }

    out_len = NGX_AUTH_COOKIE_RATE_KEY_LEN;
    if (EVP_Digest(message, len, out, &out_len, EVP_sha256(), NULL) != 1
        || out_len != NGX_AUTH_COOKIE_RATE_KEY_LEN)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_auth_cookie_rate_insert(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t **p;
    ngx_http_auth_cookie_rate_node_t *item, *other;

    for ( ;; ) {
        if (node->key < temp->key) {
            p = &temp->left;
        } else if (node->key > temp->key) {
            p = &temp->right;
        } else {
            item = (ngx_http_auth_cookie_rate_node_t *) node;
            other = (ngx_http_auth_cookie_rate_node_t *) temp;
            p = (ngx_memcmp(item->key, other->key,
                            NGX_AUTH_COOKIE_RATE_KEY_LEN) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }
        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = node->right = sentinel;
    ngx_rbt_red(node);
}


static void
ngx_http_auth_cookie_rate_expire(ngx_slab_pool_t *shpool,
    ngx_http_auth_cookie_rate_shctx_t *sh)
{
    ngx_queue_t *q;
    ngx_http_auth_cookie_rate_node_t *node;

    if (ngx_queue_empty(&sh->queue)) {
        return;
    }

    q = ngx_queue_last(&sh->queue);
    node = ngx_queue_data(q, ngx_http_auth_cookie_rate_node_t, queue);
    ngx_queue_remove(q);
    ngx_rbtree_delete(&sh->rbtree, &node->node);
    ngx_slab_free_locked(shpool, node);
}


ngx_int_t
ngx_http_auth_cookie_rate_zone_create(ngx_conf_t *cf,
    ngx_http_auth_cookie_rate_main_conf_t *conf)
{
    static ngx_str_t ip_name = ngx_string("auth_cookie_login_rate_ip");
    static ngx_str_t username_name = ngx_string("auth_cookie_login_rate_username");
    ngx_http_auth_cookie_rate_zone_ctx_t *ip_ctx, *username_ctx;
    size_t size;

    if (!conf->auth_used) {
        return NGX_OK;
    }

    size = conf->zone_size == NGX_CONF_UNSET_SIZE
           ? NGX_AUTH_COOKIE_RATE_DEFAULT_ZONE_SIZE : conf->zone_size;

    conf->ip_zone = ngx_shared_memory_add(cf, &ip_name, size,
                                          &ngx_http_auth_cookie_module);
    if (conf->ip_zone == NULL) {
        return NGX_ERROR;
    }

    conf->username_zone = ngx_shared_memory_add(cf, &username_name, size,
                                                &ngx_http_auth_cookie_module);
    if (conf->username_zone == NULL) {
        return NGX_ERROR;
    }

    ip_ctx = ngx_pcalloc(cf->pool, sizeof(*ip_ctx));
    username_ctx = ngx_pcalloc(cf->pool, sizeof(*username_ctx));
    if (ip_ctx == NULL || username_ctx == NULL) {
        return NGX_ERROR;
    }

    conf->ip_zone->init = ngx_http_auth_cookie_rate_zone_init;
    conf->ip_zone->data = ip_ctx;
    conf->username_zone->init = ngx_http_auth_cookie_rate_zone_init;
    conf->username_zone->data = username_ctx;
    return NGX_OK;
}


ngx_int_t
ngx_http_auth_cookie_rate_zone_init(ngx_shm_zone_t *zone, void *data)
{
    ngx_http_auth_cookie_rate_zone_ctx_t *old = data;
    ngx_http_auth_cookie_rate_zone_ctx_t *ctx = zone->data;
    size_t len;

    if (old != NULL) {
        ctx->shpool = old->shpool;
        ctx->sh = old->sh;
        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *) zone->shm.addr;
    if (zone->shm.exists) {
        ctx->sh = ctx->shpool->data;
        return NGX_OK;
    }

    ctx->sh = ngx_slab_alloc(ctx->shpool,
                             sizeof(ngx_http_auth_cookie_rate_shctx_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }
    ctx->shpool->data = ctx->sh;

    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_http_auth_cookie_rate_insert);
    ngx_queue_init(&ctx->sh->queue);

    len = sizeof(" in auth_cookie login rate zone \"\"") + zone->shm.name.len;
    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }
    ngx_sprintf(ctx->shpool->log_ctx,
                " in auth_cookie login rate zone \"%V\"%Z", &zone->shm.name);
    ctx->shpool->log_nomem = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_cookie_rate_bucket_check(ngx_http_request_t *r,
    ngx_shm_zone_t *zone, ngx_http_auth_cookie_rate_loc_conf_t *conf,
    ngx_addr_t *addr, ngx_str_t *username,
    ngx_http_auth_cookie_rate_bucket_conf_t *bucket)
{
    ngx_http_auth_cookie_rate_zone_ctx_t *ctx;
    ngx_http_auth_cookie_rate_shctx_t *sh;
    ngx_http_auth_cookie_rate_node_t *node, *found;
    u_char key[NGX_AUTH_COOKIE_RATE_KEY_LEN];
    uint64_t capacity, refill, used;
    ngx_msec_t now;
    ngx_msec_int_t elapsed;
    ngx_rbtree_node_t *current, *sentinel;
    uint32_t hash;
    ngx_int_t rc;

    if (zone == NULL || zone->data == NULL) {
        return NGX_ERROR;
    }
    if (ngx_http_auth_cookie_rate_key(r, conf, addr, username, key)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ctx = zone->data;
    sh = ctx->sh;
    if (sh == NULL) {
        return NGX_ERROR;
    }

    capacity = (uint64_t) bucket->capacity
               * NGX_AUTH_COOKIE_RATE_TOKEN_SCALE;
    now = ngx_current_msec;
    hash = ngx_http_auth_cookie_rate_hash(key, sizeof(key));

    ngx_shmtx_lock(&ctx->shpool->mutex);

    sentinel = sh->rbtree.sentinel;
    current = sh->rbtree.root;
    found = NULL;
    while (current != sentinel) {
        node = (ngx_http_auth_cookie_rate_node_t *) current;
        if (hash < current->key) {
            current = current->left;
        } else if (hash > current->key) {
            current = current->right;
        } else {
            rc = ngx_memcmp(key, node->key, sizeof(key));
            if (rc == 0) {
                found = node;
                break;
            }
            current = rc < 0 ? current->left : current->right;
        }
    }

    if (found == NULL) {
        found = ngx_slab_alloc_locked(ctx->shpool, sizeof(*found));
        while (found == NULL && !ngx_queue_empty(&sh->queue)) {
            ngx_http_auth_cookie_rate_expire(ctx->shpool, sh);
            found = ngx_slab_alloc_locked(ctx->shpool, sizeof(*found));
            if (found != NULL) {
                break;
            }
        }
        if (found == NULL) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return NGX_AUTH_COOKIE_RATE_DENIED;
        }
        ngx_memzero(found, sizeof(*found));
        ngx_memcpy(found->key, key, sizeof(key));
        found->node.key = hash;
        found->tokens = capacity;
        found->last = now;
        ngx_rbtree_insert(&sh->rbtree, &found->node);
        ngx_queue_insert_head(&sh->queue, &found->queue);
    } else {
        ngx_queue_remove(&found->queue);
        ngx_queue_insert_head(&sh->queue, &found->queue);

        elapsed = (ngx_msec_int_t) (now - found->last);
        /* 时钟回拨沿用原有归一规则，并重置基准以免滞留未来时间。 */
        if (elapsed < 0) {
            found->last = now;
        }
        if (elapsed < -60000) {
            elapsed = 1;
        } else if (elapsed < 0) {
            elapsed = 0;
        }

        if (found->tokens > capacity) {
            found->tokens = capacity;
        }
        if ((ngx_msec_t) elapsed >= bucket->period) {
            found->tokens = capacity;
            found->last = now;
        } else if (elapsed > 0) {
            refill = (uint64_t) elapsed * capacity / bucket->period;
            found->tokens = ngx_min(capacity, found->tokens + refill);
            if (found->tokens == capacity) {
                found->last = now;
            } else if (refill != 0) {
                /* 仅消耗实际回填对应的时间，向上取整避免超发令牌。 */
                used = (refill * bucket->period + capacity - 1) / capacity;
                found->last += (ngx_msec_t) used;
            }
        }
    }

    if (found->tokens < NGX_AUTH_COOKIE_RATE_TOKEN_SCALE) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        return NGX_AUTH_COOKIE_RATE_DENIED;
    }

    found->tokens -= NGX_AUTH_COOKIE_RATE_TOKEN_SCALE;
    ngx_shmtx_unlock(&ctx->shpool->mutex);
    return NGX_AUTH_COOKIE_RATE_ALLOWED;
}


ngx_int_t
ngx_http_auth_cookie_rate_check(ngx_http_request_t *r,
    ngx_http_auth_cookie_rate_loc_conf_t *conf, ngx_str_t *username)
{
    ngx_http_auth_cookie_rate_main_conf_t *amcf;
    ngx_http_auth_cookie_main_conf_t *main;
    ngx_addr_t addr;
    ngx_int_t rc;

    if (conf->rate == NULL) {
        return NGX_AUTH_COOKIE_RATE_ALLOWED;
    }
    if (!conf->scope_ready) {
        return NGX_ERROR;
    }

    rc = ngx_http_auth_cookie_rate_source(r, conf, &addr);
    if (rc != NGX_OK) {
        return NGX_AUTH_COOKIE_RATE_BAD_IP;
    }

    main = ngx_http_get_module_main_conf(r, ngx_http_auth_cookie_module);
    if (main == NULL) {
        return NGX_ERROR;
    }
    amcf = &main->rate;

    switch (conf->key_mode) {
    case NGX_AUTH_COOKIE_RATE_KEY_IP:
        return ngx_http_auth_cookie_rate_bucket_check(r, amcf->ip_zone, conf,
            &addr, NULL, &conf->rate->ip);

    case NGX_AUTH_COOKIE_RATE_KEY_USERNAME:
        if (username == NULL) {
            return ngx_http_auth_cookie_rate_bucket_check(r, amcf->ip_zone,
                conf, &addr, NULL, &conf->rate->ip);
        }
        return ngx_http_auth_cookie_rate_bucket_check(r, amcf->username_zone,
            conf, &addr, username, &conf->rate->username);

    case NGX_AUTH_COOKIE_RATE_KEY_IP_USERNAME:
        rc = ngx_http_auth_cookie_rate_bucket_check(r, amcf->ip_zone, conf,
            &addr, NULL, &conf->rate->ip);
        if (rc != NGX_AUTH_COOKIE_RATE_ALLOWED || username == NULL) {
            return rc;
        }
        return ngx_http_auth_cookie_rate_bucket_check(r, amcf->username_zone,
            conf, &addr, username, &conf->rate->username);

    default:
        return NGX_ERROR;
    }
}
