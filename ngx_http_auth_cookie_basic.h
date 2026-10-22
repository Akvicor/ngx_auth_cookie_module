/* ngx_http_auth_cookie_module — HTTP Basic 请求认证 */

#ifndef _NGX_HTTP_AUTH_COOKIE_BASIC_H_INCLUDED_
#define _NGX_HTTP_AUTH_COOKIE_BASIC_H_INCLUDED_

#include "ngx_http_auth_cookie_htpasswd.h"
#include "ngx_http_auth_cookie_rate_limit.h"

/*
 * 使用当前配置的用户表及登录限流校验主动发送的 Basic 凭据。
 * 成功返回 NGX_OK 并填写 user；其他认证方案返回 NGX_DECLINED；
 * 凭据无效返回 401，同源校验失败或来源 IP 无效返回 400，超出限流返回 429，
 * 内部错误返回 500。调用方直接返回状态，不发送浏览器认证挑战。
 */
ngx_int_t ngx_http_auth_cookie_basic(ngx_http_request_t *r,
    ngx_http_auth_cookie_users_t *users,
    ngx_http_auth_cookie_rate_loc_conf_t *rate, ngx_flag_t csrf,
    ngx_str_t *user);

#endif /* _NGX_HTTP_AUTH_COOKIE_BASIC_H_INCLUDED_ */
