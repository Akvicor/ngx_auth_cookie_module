/*
 * ngx_http_auth_cookie_module — cookie 签发/验签与 secret 管理实现
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "ngx_http_auth_cookie_util.h"
#include "ngx_http_auth_cookie_crypto.h"


ngx_int_t
ngx_http_auth_cookie_hmac_sha256(const u_char *key, size_t key_len,
    const u_char *message, size_t message_len, u_char *out)
{
    unsigned int  out_len = 0;

    if (HMAC(EVP_sha256(), key, (int) key_len, message, message_len,
             out, &out_len)
        == NULL
        || out_len != NGX_AUTH_COOKIE_HMAC_SHA256_LEN)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/* 签名绑定当前 host 与用户文件,防止 cookie 跨认证域重放。 */
static ngx_int_t
ngx_http_auth_cookie_session_hmac(ngx_http_request_t *r, ngx_str_t *secret,
    ngx_str_t *audience, const u_char *fingerprint, ngx_str_t *payload,
    u_char *out)
{
    ngx_str_t   host;
    u_char     *message, *p;
    size_t      len, extra;

    host = r->headers_in.server;
    if (host.len == 0 || audience == NULL || audience->len == 0
        || fingerprint == NULL)
    {
        return NGX_ERROR;
    }

    extra = 3 + NGX_AUTH_COOKIE_HMAC_SHA256_LEN;
    if (host.len > (size_t) -1 - audience->len - extra
        || payload->len > (size_t) -1 - host.len - audience->len - extra)
    {
        return NGX_ERROR;
    }

    len = host.len + 1 + audience->len + 1 + NGX_AUTH_COOKIE_HMAC_SHA256_LEN
          + 1 + payload->len;
    message = ngx_pnalloc(r->pool, len);
    if (message == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(message, host.data, host.len);
    *p++ = '\0';
    p = ngx_cpymem(p, audience->data, audience->len);
    *p++ = '\0';
    p = ngx_cpymem(p, fingerprint, NGX_AUTH_COOKIE_HMAC_SHA256_LEN);
    *p++ = '\0';
    ngx_memcpy(p, payload->data, payload->len);

    if (ngx_http_auth_cookie_hmac_sha256(secret->data, secret->len,
                                         message, len, out)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_auth_cookie_load_secret(ngx_pool_t *pool, ngx_log_t *log,
    ngx_str_t *secret_file, ngx_str_t *secret)
{
    ngx_fd_t     fd;
    ngx_file_t   file;
    ngx_file_info_t  fi;
    ssize_t      n;
    u_char      *buf;
    u_char       random_buf[32];
    size_t       secret_len;

    if (secret->len > 0) {
        return NGX_OK;
    }

    fd = ngx_open_file(secret_file->data,
                       NGX_FILE_RDONLY|NGX_FILE_NONBLOCK,
                       NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_err_t  err = ngx_errno;

        if (err != NGX_ENOENT) {
            ngx_log_error(NGX_LOG_ERR, log, err,
                          "auth_cookie: open secret file \"%s\" failed",
                          secret_file->data);
            return NGX_ERROR;
        }

        /* 文件不存在:生成随机密钥并写入(0600) */
        if (RAND_bytes(random_buf, sizeof(random_buf)) != 1) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "auth_cookie: RAND_bytes() failed");
            return NGX_ERROR;
        }

        secret_len = sizeof(random_buf) * 2;
        secret->data = ngx_palloc(pool, secret_len + 1);
        if (secret->data == NULL) {
            return NGX_ERROR;
        }
        ngx_http_auth_cookie_hex(random_buf, sizeof(random_buf), secret->data);
        ngx_explicit_memzero(random_buf, sizeof(random_buf));
        secret->data[secret_len] = '\0';

        fd = ngx_open_file(secret_file->data, NGX_FILE_WRONLY,
                           NGX_FILE_CREATE_OR_OPEN|NGX_FILE_TRUNCATE|O_EXCL,
                           NGX_FILE_OWNER_ACCESS);
        if (fd == NGX_INVALID_FILE) {
            if (ngx_errno == NGX_EEXIST) {
                ngx_explicit_memzero(secret->data, secret_len);
                fd = ngx_open_file(secret_file->data,
                                   NGX_FILE_RDONLY|NGX_FILE_NONBLOCK,
                                   NGX_FILE_OPEN, 0);
                if (fd != NGX_INVALID_FILE) {
                    goto read_existing;
                }
            }
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                          "auth_cookie: create secret file \"%s\" failed",
                          secret_file->data);
            return NGX_ERROR;
        }

        n = ngx_write_fd(fd, secret->data, secret_len);
        ngx_close_file(fd);

        if (n != (ssize_t) secret_len) {
            (void) ngx_delete_file(secret_file->data);
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                          "auth_cookie: write secret file \"%s\" failed",
                          secret_file->data);
            return NGX_ERROR;
        }

        secret->len = secret_len;
        return NGX_OK;
    }

read_existing:

    /* 文件已存在:仅接受权限收紧的普通文件与至少 256 位密钥。 */
    ngx_memzero(&file, sizeof(ngx_file_t));
    file.fd = fd;
    file.name = *secret_file;
    file.log = log;

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR || !ngx_is_file(&fi)) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "auth_cookie: secret file \"%s\" is not a regular file",
                      secret_file->data);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    if ((ngx_file_access(&fi) & 0077) != 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_cookie: secret file \"%s\" must not grant group or other access",
                      secret_file->data);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    if (fi.st_uid != geteuid()) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_cookie: secret file \"%s\" must be owned by the nginx master user",
                      secret_file->data);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    if (ngx_file_size(&fi) < 32 || ngx_file_size(&fi) > 129) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_cookie: secret file \"%s\" must contain 32..128 bytes",
                      secret_file->data);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    secret_len = (size_t) ngx_file_size(&fi);
    buf = ngx_palloc(pool, secret_len + 1);
    if (buf == NULL) {
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    n = ngx_read_file(&file, buf, secret_len, 0);
    ngx_close_file(fd);

    if (n != (ssize_t) secret_len) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_cookie: read secret file \"%s\" failed",
                      secret_file->data);
        return NGX_ERROR;
    }

    buf[secret_len] = '\0';
    while (secret_len > 0 && (buf[secret_len - 1] == '\n'
           || buf[secret_len - 1] == '\r'))
    {
        secret_len--;
    }

    if (secret_len < 32
        || ngx_strlchr(buf, buf + secret_len, '\0') != NULL)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_cookie: secret file \"%s\" is invalid or too short",
                      secret_file->data);
        return NGX_ERROR;
    }

    secret->data = buf;
    secret->len = secret_len;
    return NGX_OK;
}


ngx_int_t
ngx_http_auth_cookie_sign(ngx_http_request_t *r,
    ngx_str_t *secret, ngx_str_t *audience, const u_char *fingerprint,
    time_t session_ttl, ngx_str_t *user, ngx_str_t *cookie)
{
    u_char     *buf, *p;
    u_char      exp_str[20];
    size_t      exp_len;
    time_t      exp, now;
    uint64_t    max_time;
    u_char      nonce[16], nonce_hex[32];
    u_char      sig[NGX_AUTH_COOKIE_HMAC_SHA256_LEN];
    ngx_str_t   payload, raw;
    u_char     *raw_buf;

    if (secret->len == 0) {
        return NGX_ERROR;
    }

    if (user->len == 0 || user->len > NGX_AUTH_COOKIE_MAX_USER_LEN) {
        return NGX_ERROR;
    }

    now = ngx_time();
    max_time = ((uint64_t) 1 << (sizeof(time_t) * 8 - 1)) - 1;
    if (session_ttl <= 0
        || (uint64_t) session_ttl > max_time - (uint64_t) now)
    {
        return NGX_ERROR;
    }
    exp = now + session_ttl;

    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        return NGX_ERROR;
    }
    ngx_http_auth_cookie_hex(nonce, sizeof(nonce), nonce_hex);
    ngx_explicit_memzero(nonce, sizeof(nonce));

    exp_len = ngx_sprintf(exp_str, "%T", exp) - exp_str;

    /* raw = user ":" exp ":" nonce */
    raw_buf = ngx_pnalloc(r->pool,
                          user->len + 1 + exp_len + 1 + sizeof(nonce_hex));
    if (raw_buf == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(raw_buf, user->data, user->len);
    raw_buf[user->len] = ':';
    p = ngx_sprintf(raw_buf + user->len + 1, "%T", exp);
    *p++ = ':';
    ngx_memcpy(p, nonce_hex, sizeof(nonce_hex));

    raw.data = raw_buf;
    raw.len = user->len + 1 + exp_len + 1 + sizeof(nonce_hex);

    /* payload = base64url(raw) */
    if (ngx_http_auth_cookie_b64url_encode(r->pool, raw.data, raw.len,
                                           &payload)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_auth_cookie_session_hmac(r, secret, audience, fingerprint,
                                          &payload, sig)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* cookie = payload "." hex(sig) */
    buf = ngx_pnalloc(r->pool, payload.len + 1 + NGX_AUTH_COOKIE_SIG_LEN * 2);
    if (buf == NULL) {
        return NGX_ERROR;
    }
    p = ngx_cpymem(buf, payload.data, payload.len);
    *p++ = '.';
    ngx_http_auth_cookie_hex(sig, NGX_AUTH_COOKIE_SIG_LEN, p);

    cookie->data = buf;
    cookie->len = payload.len + 1 + NGX_AUTH_COOKIE_SIG_LEN * 2;

    return NGX_OK;
}


ngx_int_t
ngx_http_auth_cookie_parse(ngx_http_request_t *r, ngx_str_t *cookie_str,
    ngx_http_auth_cookie_session_t *session)
{
    u_char     *dot, *colon, *nonce_sep;
    ngx_str_t   payload, raw, nonce_hex;
    u_char      nonce[16];

    if (cookie_str->len == 0) {
        return NGX_DECLINED;
    }

    dot = ngx_strlchr(cookie_str->data, cookie_str->data + cookie_str->len,
                      '.');
    if (dot == NULL) {
        return NGX_DECLINED;
    }

    payload.data = cookie_str->data;
    payload.len = dot - cookie_str->data;
    if (payload.len == 0
        || cookie_str->data + cookie_str->len - (dot + 1)
           != NGX_AUTH_COOKIE_SIG_LEN * 2)
    {
        return NGX_DECLINED;
    }

    if (ngx_http_auth_cookie_b64url_decode(r->pool, payload.data,
                                           payload.len, &raw)
        != NGX_OK)
    {
        return NGX_DECLINED;
    }

    colon = ngx_strlchr(raw.data, raw.data + raw.len, ':');
    if (colon == NULL) {
        return NGX_DECLINED;
    }

    session->user.data = raw.data;
    session->user.len = colon - raw.data;
    if (session->user.len == 0
        || session->user.len > NGX_AUTH_COOKIE_MAX_USER_LEN)
    {
        return NGX_DECLINED;
    }

    nonce_sep = ngx_strlchr(colon + 1, raw.data + raw.len, ':');
    if (nonce_sep == NULL) {
        return NGX_DECLINED;
    }

    nonce_hex.data = nonce_sep + 1;
    nonce_hex.len = raw.data + raw.len - (nonce_sep + 1);
    if (nonce_hex.len != sizeof(nonce) * 2
        || ngx_http_auth_cookie_hex2bin(nonce_hex.data, nonce_hex.len, nonce)
           != NGX_OK)
    {
        return NGX_DECLINED;
    }

    if (ngx_http_auth_cookie_hex2bin(dot + 1, NGX_AUTH_COOKIE_SIG_LEN * 2,
                                    session->signature)
        != NGX_OK)
    {
        return NGX_DECLINED;
    }

    session->payload = payload;
    session->expiry.data = colon + 1;
    session->expiry.len = nonce_sep - (colon + 1);
    return NGX_OK;
}


ngx_int_t
ngx_http_auth_cookie_verify(ngx_http_request_t *r,
    ngx_str_t *secret, ngx_str_t *audience, const u_char *fingerprint,
    ngx_http_auth_cookie_session_t *session)
{
    u_char expect_sig[NGX_AUTH_COOKIE_HMAC_SHA256_LEN];
    time_t exp, now;

    if (secret->len == 0) {
        return NGX_DECLINED;
    }

    if (ngx_http_auth_cookie_session_hmac(r, secret, audience, fingerprint,
                                          &session->payload, expect_sig)
        != NGX_OK)
    {
        return NGX_DECLINED;
    }

    if (ngx_http_auth_cookie_constant_eq(session->signature, expect_sig,
                                         NGX_AUTH_COOKIE_HMAC_SHA256_LEN)
        != NGX_OK)
    {
        return NGX_DECLINED;
    }

    exp = ngx_atoi(session->expiry.data, session->expiry.len);
    if (exp == NGX_ERROR) {
        return NGX_DECLINED;
    }

    now = ngx_time();
    if (exp <= now) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}
