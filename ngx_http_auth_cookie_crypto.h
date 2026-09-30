/*
 * ngx_http_auth_cookie_module — cookie 签发/验签与 secret 管理
 *
 * cookie 格式:
 *   payload = base64url(user ":" decimal(exp) ":" hex(nonce))
 *   sig     = hex(HMAC-SHA256(secret, host + audience + fingerprint + payload))
 *   cookie  = payload "." sig
 *
 * secret 从文件读取;文件不存在时生成 256 位随机密钥写入(权限 0600)。
 */

#ifndef _NGX_HTTP_AUTH_COOKIE_CRYPTO_H_INCLUDED_
#define _NGX_HTTP_AUTH_COOKIE_CRYPTO_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_AUTH_COOKIE_MAX_USER_LEN   128
#define NGX_AUTH_COOKIE_SIG_LEN        32
#define NGX_AUTH_COOKIE_HMAC_SHA256_LEN 32

/* HMAC-SHA256,结果写入 out(至少 NGX_AUTH_COOKIE_HMAC_SHA256_LEN 字节) */
ngx_int_t ngx_http_auth_cookie_hmac_sha256(const u_char *key, size_t key_len,
    const u_char *message, size_t message_len, u_char *out);

/* 签发 cookie;成功返回 NGX_OK 且 *cookie 指向 pool 分配的结果 */
ngx_int_t ngx_http_auth_cookie_sign(ngx_http_request_t *r,
    ngx_str_t *secret, ngx_str_t *audience, const u_char *fingerprint,
    time_t session_ttl, ngx_str_t *user, ngx_str_t *cookie);

/* 解析结果尚未认证；仅在验签通过后用于请求身份。 */
typedef struct {
    ngx_str_t  payload;
    ngx_str_t  user;
    ngx_str_t  expiry;
    u_char     signature[NGX_AUTH_COOKIE_SIG_LEN];
} ngx_http_auth_cookie_session_t;

/* 一次解析 Cookie 结构，用户名用于查找当前密码指纹。 */
ngx_int_t ngx_http_auth_cookie_parse(ngx_http_request_t *r,
    ngx_str_t *cookie, ngx_http_auth_cookie_session_t *session);

/* 绑定当前用户指纹验签并校验过期；失败返回 NGX_DECLINED。 */
ngx_int_t ngx_http_auth_cookie_verify(ngx_http_request_t *r,
    ngx_str_t *secret, ngx_str_t *audience, const u_char *fingerprint,
    ngx_http_auth_cookie_session_t *session);

/* 从文件载入 secret;不存在则生成(0600)。结果使用传入 pool 的生命周期。 */
ngx_int_t ngx_http_auth_cookie_load_secret(ngx_pool_t *pool, ngx_log_t *log,
    ngx_str_t *secret_file, ngx_str_t *secret);

#endif /* _NGX_HTTP_AUTH_COOKIE_CRYPTO_H_INCLUDED_ */
