/* 模块级配置按文件快照与登录限流分别组织。 */
#ifndef _NGX_HTTP_AUTH_COOKIE_MODULE_H_INCLUDED_
#define _NGX_HTTP_AUTH_COOKIE_MODULE_H_INCLUDED_

#include "ngx_http_auth_cookie_file_cache.h"
#include "ngx_http_auth_cookie_rate_limit.h"

/* 两种配置均随 nginx 配置周期创建，限流状态由共享内存持有。 */
typedef struct {
    ngx_http_auth_cookie_rate_main_conf_t  rate;
    ngx_http_auth_cookie_file_cache_t      files;
} ngx_http_auth_cookie_main_conf_t;

#endif
