/*
 * ngx_http_auth_cookie_module — 通用工具函数
 *
 * 提供 base64url 编解码、十六进制编解码、URL 解码、常量时间比较、
 * next 参数开放重定向防护等与 nginx 业务无关的纯工具。
 */

#ifndef _NGX_HTTP_AUTH_COOKIE_UTIL_H_INCLUDED_
#define _NGX_HTTP_AUTH_COOKIE_UTIL_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* base64url 编码(无填充);结果写入 pool,返回 NGX_OK */
ngx_int_t ngx_http_auth_cookie_b64url_encode(ngx_pool_t *pool,
    const u_char *in, size_t in_len, ngx_str_t *out);

/* base64url 解码(无填充);非法字符返回 NGX_ERROR */
ngx_int_t ngx_http_auth_cookie_b64url_decode(ngx_pool_t *pool,
    const u_char *in, size_t in_len, ngx_str_t *out);

/* 二进制转小写十六进制,写入 dst(需 2*len 字节),返回结尾指针 */
u_char *ngx_http_auth_cookie_hex(const u_char *src, size_t len, u_char *dst);

/* 十六进制转二进制;len 必须为偶数,out 需 len/2 字节 */
ngx_int_t ngx_http_auth_cookie_hex2bin(const u_char *hex, size_t len,
    u_char *out);

/* 常量时间相等比较;返回 NGX_OK 相等,NGX_ERROR 不等 */
ngx_int_t ngx_http_auth_cookie_constant_eq(const u_char *a, const u_char *b,
    size_t len);

/* application/x-www-form-urlencoded 解码(+ → 空格,%XX → 字节) */
ngx_int_t ngx_http_auth_cookie_unescape(ngx_pool_t *pool, ngx_str_t *in,
    ngx_str_t *out);

/*
 * 校验 next 参数,防开放重定向:
 * 允许站内相对路径(以单个 / 开头,非 //)或同 host 绝对 URL。
 * 非法时置 next->len = 0。
 */
void ngx_http_auth_cookie_sanitize_next(ngx_http_request_t *r, ngx_str_t *next);

#endif /* _NGX_HTTP_AUTH_COOKIE_UTIL_H_INCLUDED_ */
