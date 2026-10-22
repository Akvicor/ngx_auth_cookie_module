/* ngx_http_auth_cookie_module — HTTP Basic 请求认证 */

#include "ngx_http_auth_cookie_basic.h"
#include "ngx_http_auth_cookie_module.h"


ngx_int_t
ngx_http_auth_cookie_basic(ngx_http_request_t *r,
    ngx_http_auth_cookie_users_t *users,
    ngx_http_auth_cookie_rate_loc_conf_t *rate, ngx_flag_t csrf,
    ngx_str_t *user)
{
    ngx_str_t                     value, *username;
    ngx_http_auth_cookie_user_t   *entry;
    ngx_int_t                     rc, parsed, csrf_status;

    if (r->headers_in.authorization == NULL) {
        return NGX_DECLINED;
    }

    value = r->headers_in.authorization->value;
    if (value.len < sizeof("Basic") - 1
        || ngx_strncasecmp(value.data, (u_char *) "Basic",
                           sizeof("Basic") - 1) != 0
        || (value.len > sizeof("Basic") - 1
            && value.data[sizeof("Basic") - 1] != ' '
            && value.data[sizeof("Basic") - 1] != '\t'))
    {
        return NGX_DECLINED;
    }

    csrf_status = ngx_http_auth_cookie_check_csrf(r, csrf);
    parsed = NGX_DECLINED;
    if (csrf_status == NGX_OK) {
        /* 复用 core 的解析及 $remote_user 语义，保留请求头供上游和其他模块使用。 */
        parsed = ngx_http_auth_basic_user(r);
    }
    if (parsed == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    username = NULL;
    if (parsed == NGX_OK && r->headers_in.passwd.len != 0
        && ngx_http_auth_cookie_valid_username(&r->headers_in.user) == NGX_OK)
    {
        username = &r->headers_in.user;
    }

    /* 与表单一致：密码校验前预扣，CSRF、空凭据及无效用户名按 IP 计数。 */
    rc = ngx_http_auth_cookie_rate_check(r, rate, username);
    if (rc == NGX_AUTH_COOKIE_RATE_DENIED) {
        return NGX_HTTP_TOO_MANY_REQUESTS;
    }
    if (rc == NGX_AUTH_COOKIE_RATE_BAD_IP) {
        return NGX_HTTP_BAD_REQUEST;
    }
    if (rc != NGX_AUTH_COOKIE_RATE_ALLOWED) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (csrf_status != NGX_OK) {
        return csrf_status;
    }

    if (username == NULL
        || ngx_http_auth_cookie_valid_password(&r->headers_in.passwd) != NGX_OK)
    {
        return NGX_HTTP_UNAUTHORIZED;
    }

    entry = ngx_http_auth_cookie_lookup_user(users, &r->headers_in.user);
    if (entry == NULL) {
        return NGX_HTTP_UNAUTHORIZED;
    }

    rc = ngx_http_auth_cookie_check_password(r, &r->headers_in.passwd,
                                            &entry->hash);
    if (rc == NGX_DECLINED) {
        return NGX_HTTP_UNAUTHORIZED;
    }
    if (rc == NGX_OK) {
        ngx_http_auth_cookie_rate_refund(r, rate);
        *user = r->headers_in.user;
    }

    return rc;
}
