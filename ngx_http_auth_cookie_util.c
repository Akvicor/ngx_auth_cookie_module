/*
 * ngx_http_auth_cookie_module — 通用工具函数实现
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_auth_cookie_util.h"


ngx_int_t
ngx_http_auth_cookie_b64url_encode(ngx_pool_t *pool,
    const u_char *in, size_t in_len, ngx_str_t *out)
{
    static const u_char  tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t     out_len, i, j;
    u_char    *p;

    if (in_len == 0) {
        out->len = 0;
        out->data = NULL;
        return NGX_OK;
    }

    out_len = ((in_len + 2) / 3) * 4;
    if (in_len % 3 == 1) {
        out_len -= 2;
    } else if (in_len % 3 == 2) {
        out_len -= 1;
    }

    p = ngx_pnalloc(pool, out_len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    for (i = 0, j = 0; i + 3 <= in_len; i += 3, j += 4) {
        p[j]     = tbl[in[i] >> 2];
        p[j + 1] = tbl[((in[i] & 0x03) << 4) | (in[i + 1] >> 4)];
        p[j + 2] = tbl[((in[i + 1] & 0x0f) << 2) | (in[i + 2] >> 6)];
        p[j + 3] = tbl[in[i + 2] & 0x3f];
    }

    if (in_len % 3 == 1) {
        p[j]     = tbl[in[i] >> 2];
        p[j + 1] = tbl[(in[i] & 0x03) << 4];
        j += 2;
    } else if (in_len % 3 == 2) {
        p[j]     = tbl[in[i] >> 2];
        p[j + 1] = tbl[((in[i] & 0x03) << 4) | (in[i + 1] >> 4)];
        p[j + 2] = tbl[(in[i + 1] & 0x0f) << 2];
        j += 3;
    }

    out->data = p;
    out->len = j;
    return NGX_OK;
}


ngx_int_t
ngx_http_auth_cookie_b64url_decode(ngx_pool_t *pool,
    const u_char *in, size_t in_len, ngx_str_t *out)
{
    u_char    val[256];
    u_char    d;
    size_t    out_len, i, j, m;
    u_char   *p, quad[4];

    if (in_len == 0 || in_len % 4 == 1) {
        return NGX_ERROR;
    }

    ngx_memzero(val, sizeof(val));
    for (i = 0; i < 26; i++) {
        val['A' + i] = (u_char) i;
        val['a' + i] = (u_char) (26 + i);
    }
    for (i = 0; i < 10; i++) {
        val['0' + i] = (u_char) (52 + i);
    }
    val['-'] = 62;
    val['_'] = 63;

    out_len = (in_len / 4) * 3;
    if (in_len % 4 == 2) {
        out_len += 1;
    } else if (in_len % 4 == 3) {
        out_len += 2;
    }

    p = ngx_pnalloc(pool, out_len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    j = 0;
    for (i = 0; i < in_len; i += 4) {
        m = 0;
        while (m < 4 && i + m < in_len) {
            d = val[in[i + m]];
            /* 值为 0 的合法字符只有 'A';其他 0 值均为非法 */
            if (d == 0 && in[i + m] != 'A') {
                return NGX_ERROR;
            }
            quad[m] = d;
            m++;
        }
        if (m == 4) {
            p[j++] = (u_char) ((quad[0] << 2) | (quad[1] >> 4));
            p[j++] = (u_char) ((quad[1] << 4) | (quad[2] >> 2));
            p[j++] = (u_char) ((quad[2] << 6) | quad[3]);
        } else if (m == 3) {
            p[j++] = (u_char) ((quad[0] << 2) | (quad[1] >> 4));
            p[j++] = (u_char) ((quad[1] << 4) | (quad[2] >> 2));
        } else if (m == 2) {
            p[j++] = (u_char) ((quad[0] << 2) | (quad[1] >> 4));
        }
    }

    out->data = p;
    out->len = j;
    return NGX_OK;
}


u_char *
ngx_http_auth_cookie_hex(const u_char *src, size_t len, u_char *dst)
{
    static const u_char  hexdig[] = "0123456789abcdef";
    size_t               i;

    for (i = 0; i < len; i++) {
        dst[i * 2] = hexdig[src[i] >> 4];
        dst[i * 2 + 1] = hexdig[src[i] & 0xf];
    }
    return dst + len * 2;
}


ngx_int_t
ngx_http_auth_cookie_hex2bin(const u_char *hex, size_t len, u_char *out)
{
    size_t    i;
    u_char    hi, lo;

    if (len % 2 != 0) {
        return NGX_ERROR;
    }

    for (i = 0; i < len; i += 2) {
        hi = hex[i];
        lo = hex[i + 1];

        if (hi >= '0' && hi <= '9') {
            hi -= '0';
        } else if (hi >= 'a' && hi <= 'f') {
            hi = hi - 'a' + 10;
        } else if (hi >= 'A' && hi <= 'F') {
            hi = hi - 'A' + 10;
        } else {
            return NGX_ERROR;
        }

        if (lo >= '0' && lo <= '9') {
            lo -= '0';
        } else if (lo >= 'a' && lo <= 'f') {
            lo = lo - 'a' + 10;
        } else if (lo >= 'A' && lo <= 'F') {
            lo = lo - 'A' + 10;
        } else {
            return NGX_ERROR;
        }

        out[i / 2] = (u_char) ((hi << 4) | lo);
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_auth_cookie_constant_eq(const u_char *a, const u_char *b, size_t len)
{
    u_char    diff = 0;
    size_t    i;

    for (i = 0; i < len; i++) {
        diff |= (u_char) (a[i] ^ b[i]);
    }

    return (diff == 0) ? NGX_OK : NGX_ERROR;
}


ngx_int_t
ngx_http_auth_cookie_unescape(ngx_pool_t *pool, ngx_str_t *in, ngx_str_t *out)
{
    u_char     *p, *dst;
    size_t      i;
    ngx_int_t   hi, lo;

    if (in->len > 4096) {
        return NGX_ERROR;
    }

    dst = ngx_pnalloc(pool, in->len);
    if (dst == NULL) {
        return NGX_ERROR;
    }

    p = dst;
    for (i = 0; i < in->len; i++) {
        if (in->data[i] == '+') {
            *p++ = ' ';
            continue;
        }
        if (in->data[i] == '%' && i + 2 < in->len) {
            hi = in->data[i + 1];
            lo = in->data[i + 2];
            if (hi >= '0' && hi <= '9') {
                hi -= '0';
            } else if (hi >= 'a' && hi <= 'f') {
                hi = hi - 'a' + 10;
            } else if (hi >= 'A' && hi <= 'F') {
                hi = hi - 'A' + 10;
            } else {
                goto literal;
            }
            if (lo >= '0' && lo <= '9') {
                lo -= '0';
            } else if (lo >= 'a' && lo <= 'f') {
                lo = lo - 'a' + 10;
            } else if (lo >= 'A' && lo <= 'F') {
                lo = lo - 'A' + 10;
            } else {
                goto literal;
            }
            *p++ = (u_char) ((hi << 4) | lo);
            i += 2;
            continue;
        }
    literal:
        *p++ = in->data[i];
    }

    out->data = dst;
    out->len = p - dst;
    return NGX_OK;
}


/*
 * 校验 next 参数,防开放重定向。
 * next 全程保持 URI 编码形态:校验在解码副本上进行,输出保持编码值,
 * 使登录后回跳目标与原始请求的编码语义一致(%23/%3F/%25 等不变形)。
 * 允许站内相对路径(解码后以单个 / 开头,非 //)或同 host 绝对 URL。
 * 非法时置 next->len = 0。
 */
void
ngx_http_auth_cookie_sanitize_next(ngx_http_request_t *r, ngx_str_t *next)
{
    ngx_str_t   decoded, authority, request_host;
    u_char     *p, *last, *dpath;
    size_t      scheme_len;

    if (next->len == 0) {
        return;
    }

    /* 编码原文中的裸 '#' 会在 Location 中成为 fragment 分隔符,拒绝;
       合法编码 %23 不受影响。 */
    if (ngx_strlchr(next->data, next->data + next->len, '#') != NULL) {
        next->len = 0;
        return;
    }

    if (ngx_http_auth_cookie_unescape(r->pool, next, &decoded) != NGX_OK) {
        next->len = 0;
        return;
    }

    /* 解码副本不允许控制字符、空格或反斜杠。 */
    for (p = decoded.data; p < decoded.data + decoded.len; p++) {
        if (*p <= 0x20 || *p == 0x7f || *p == '\\') {
            next->len = 0;
            return;
        }
    }

    /* 相对路径(编码形态以 / 开头):解码副本须以单个 / 开头;输出编码原文。 */
    if (next->data[0] == '/') {
        if (decoded.len == 0 || decoded.data[0] != '/'
            || (decoded.len >= 2 && decoded.data[1] == '/'))
        {
            next->len = 0;
        }
        return;
    }

    /* 绝对 URL:编码形态必须以字面 http(s):// 开头,authority 与 Host 一致。 */
    if (next->len >= sizeof("https://") - 1
        && ngx_strncasecmp(next->data, (u_char *) "https://",
                           sizeof("https://") - 1) == 0)
    {
        scheme_len = sizeof("https://") - 1;
    } else if (next->len >= sizeof("http://") - 1
               && ngx_strncasecmp(next->data, (u_char *) "http://",
                                  sizeof("http://") - 1) == 0)
    {
        scheme_len = sizeof("http://") - 1;
    } else {
        next->len = 0;
        return;
    }

    p = decoded.data + scheme_len;
    last = decoded.data + decoded.len;
    dpath = ngx_strlchr(p, last, '/');

    authority.data = p;
    authority.len = (dpath == NULL) ? (size_t) (last - p)
                                    : (size_t) (dpath - p);

    if (r->headers_in.host != NULL) {
        request_host = r->headers_in.host->value;
    } else {
        request_host = r->headers_in.server;
    }

    if (authority.len == 0 || authority.len != request_host.len
        || ngx_strncasecmp(authority.data, request_host.data,
                           authority.len) != 0)
    {
        next->len = 0;
        return;
    }

    if (dpath == NULL) {
        next->data = (u_char *) "/";
        next->len = 1;
        return;
    }

    /* 转换后的 path 也必须以单个 / 开头,防止 // 形成协议相对重定向。 */
    if (dpath + 1 < last && dpath[1] == '/') {
        next->len = 0;
        return;
    }

    /* 输出编码原文的 path 及之后部分,保留其中的 %XX 编码。 */
    p = ngx_strlchr(next->data + scheme_len, next->data + next->len, '/');
    if (p == NULL) {
        next->data = (u_char *) "/";
        next->len = 1;
        return;
    }

    next->len = (next->data + next->len) - p;
    next->data = p;
}
