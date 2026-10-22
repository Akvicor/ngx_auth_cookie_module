/*
 * 单元测试桩:ngx_http.h 的最小替代。
 * 只提供 crypto.c / util.c 用到的请求结构字段。
 */

#ifndef TEST_NGX_HTTP_H
#define TEST_NGX_HTTP_H

#include <ngx_config.h>
#include <ngx_core.h>

typedef struct {
    ngx_str_t  key;
    ngx_str_t  value;
} ngx_table_elt_t;

typedef struct {
    ngx_pool_t  *pool;
    struct {
        ngx_str_t          server;
        ngx_table_elt_t   *host;
    } headers_in;
} ngx_http_request_t;

#endif
