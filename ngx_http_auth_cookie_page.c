/*
 * ngx_http_auth_cookie_module — 登录页渲染实现
 *
 * auth_cookie_page 三态:
 *   basic   - 内置简洁登录页(默认)
 *   premium - 内置精美登录页
 *   /绝对路径.html - 使用外部 HTML 文件(自定义页面)
 *
 * 登录页为 HTML 表单,POST username/password 到登录 URI。
 * 自定义页面约定:替换占位符 {{title}}/{{error}}/{{next}}/{{action}}。
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_auth_cookie_page.h"

#define NGX_AUTH_COOKIE_PAGE_FILE_MAX  (128 * 1024)
#define NGX_AUTH_COOKIE_PAGE_MAX       (512 * 1024)

/* 内置 basic 登录页 */
static const u_char ngx_http_auth_cookie_page_basic[] =
    "<!DOCTYPE html>"
    "<html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
    "<title>{{title}}</title>"
    "<style>"
    "body{font-family:system-ui,-apple-system,sans-serif;background:#f5f6f8;"
    "display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}"
    ".card{background:#fff;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,.08);"
    "padding:40px 32px;width:100%;max-width:340px}"
    "h1{font-size:20px;margin:0 0 24px;color:#1a1a1a}"
    "label{display:block;font-size:13px;color:#555;margin:12px 0 6px}"
    "input{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid #ddd;"
    "border-radius:6px;font-size:14px;outline:none}"
    "input:focus{border-color:#4c9aff}"
    "button{margin-top:20px;width:100%;padding:11px;background:#4c9aff;color:#fff;"
    "border:0;border-radius:6px;font-size:15px;cursor:pointer}"
    "button:hover{background:#3a85e0}"
    ".error{color:#d93025;font-size:13px;margin-top:12px;min-height:18px}"
    "</style></head><body>"
    "<form class=\"card\" method=\"post\" action=\"{{action}}\">"
    "<h1>{{title}}</h1>"
    "<input type=\"hidden\" name=\"next\" value=\"{{next}}\">"
    "<label for=\"u\">用户名</label>"
    "<input id=\"u\" name=\"username\" autocomplete=\"username\" required autofocus>"
    "<label for=\"p\">密码</label>"
    "<input id=\"p\" name=\"password\" type=\"password\" autocomplete=\"current-password\" required>"
    "<button type=\"submit\">登录</button>"
    "<div class=\"error\">{{error}}</div>"
    "</form></body></html>";

/* 内置 premium 登录页(更精美) */
static const u_char ngx_http_auth_cookie_page_premium[] =
    "<!DOCTYPE html>"
    "<html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
    "<title>{{title}}</title>"
    "<style>"
    ":root{--primary:#2563eb;--bg:#0f172a;--card:#1e293b;--text:#e2e8f0;--muted:#94a3b8}"
    "*{box-sizing:border-box}"
    "body{font-family:'Inter',system-ui,-apple-system,sans-serif;background:"
    "radial-gradient(1200px 600px at 20% 0%,#1e3a8a55,transparent 60%),"
    "radial-gradient(800px 500px at 90% 90%,#4f46e555,transparent 60%),var(--bg);"
    "color:var(--text);display:flex;align-items:center;justify-content:center;"
    "min-height:100vh;margin:0}"
    ".card{background:var(--card);border:1px solid #334155;border-radius:16px;"
    "padding:48px 40px;width:100%;max-width:380px;box-shadow:0 24px 48px rgba(0,0,0,.4)}"
    "h1{font-size:22px;font-weight:600;margin:0 0 28px;letter-spacing:.5px}"
    "label{display:block;font-size:13px;color:var(--muted);margin:16px 0 6px}"
    "input{width:100%;box-sizing:border-box;padding:12px 14px;background:#0f172a;"
    "border:1px solid #334155;border-radius:8px;color:var(--text);font-size:14px;outline:none}"
    "input:focus{border-color:var(--primary);box-shadow:0 0 0 3px #2563eb33}"
    "button{margin-top:24px;width:100%;padding:13px;background:var(--primary);color:#fff;"
    "border:0;border-radius:8px;font-size:15px;font-weight:500;cursor:pointer;"
    "transition:background .15s}"
    "button:hover{background:#1d4ed8}"
    ".error{color:#f87171;font-size:13px;margin-top:14px;min-height:18px}"
    "</style></head><body>"
    "<form class=\"card\" method=\"post\" action=\"{{action}}\">"
    "<h1>{{title}}</h1>"
    "<input type=\"hidden\" name=\"next\" value=\"{{next}}\">"
    "<label for=\"u\">用户名</label>"
    "<input id=\"u\" name=\"username\" autocomplete=\"username\" required autofocus>"
    "<label for=\"p\">密码</label>"
    "<input id=\"p\" name=\"password\" type=\"password\" autocomplete=\"current-password\" required>"
    "<button type=\"submit\">登录</button>"
    "<div class=\"error\">{{error}}</div>"
    "</form></body></html>";

/* 返回内置页面内容;未知时返回 NULL(调用方已校验,正常不会走到) */
const u_char *
ngx_http_auth_cookie_builtin_page(ngx_str_t *page)
{
    if (page->len == sizeof("basic") - 1
        && ngx_strncmp(page->data, "basic", sizeof("basic") - 1) == 0)
    {
        return ngx_http_auth_cookie_page_basic;
    }

    if (page->len == sizeof("premium") - 1
        && ngx_strncmp(page->data, "premium", sizeof("premium") - 1) == 0)
    {
        return ngx_http_auth_cookie_page_premium;
    }

    return NULL;
}

/* 从外部 HTML 文件读内容(成功返回 NGX_OK, *content 指向 pool 分配的内存) */
ngx_int_t
ngx_http_auth_cookie_load_page(ngx_pool_t *pool, ngx_log_t *log,
    ngx_str_t *path, ngx_str_t *content)
{
    ngx_fd_t     fd;
    ngx_file_t   file;
    ngx_file_info_t  fi;
    ssize_t      n;
    u_char      *buf;
    size_t       size;

    fd = ngx_open_file(path->data,
                       NGX_FILE_RDONLY|NGX_FILE_NONBLOCK|O_NOFOLLOW,
                       NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "auth_cookie: open login page \"%s\" failed", path->data);
        return NGX_ERROR;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.fd = fd;
    file.name = *path;
    file.log = log;

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR || !ngx_is_file(&fi)) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "auth_cookie: login page \"%s\" is not a regular file",
                      path->data);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    if (ngx_file_size(&fi) <= 0
        || ngx_file_size(&fi) > NGX_AUTH_COOKIE_PAGE_FILE_MAX)
    {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "auth_cookie: login page \"%s\" must be 1..128KB",
                      path->data);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    size = (size_t) ngx_file_size(&fi);

    buf = ngx_pnalloc(pool, size);
    if (buf == NULL) {
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    n = ngx_read_file(&file, buf, size, 0);
    if (n == NGX_ERROR || (size_t) n != size) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "auth_cookie: read login page \"%s\" failed", path->data);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    ngx_close_file(fd);

    if (ngx_strlchr(buf, buf + size, '\0') != NULL) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "auth_cookie: login page \"%s\" contains NUL",
                      path->data);
        return NGX_ERROR;
    }

    content->data = buf;
    content->len = n;
    return NGX_OK;
}

/* HTML 转义一个字符,返回写入 dst 的字节数 */
static size_t
ngx_http_auth_cookie_html_escape_char(u_char c, u_char *dst)
{
    switch (c) {
    case '<':
        ngx_memcpy(dst, "&lt;", 4); return 4;
    case '>':
        ngx_memcpy(dst, "&gt;", 4); return 4;
    case '&':
        ngx_memcpy(dst, "&amp;", 5); return 5;
    case '"':
        ngx_memcpy(dst, "&quot;", 6); return 6;
    case '\'':
        ngx_memcpy(dst, "&#39;", 5); return 5;
    case '=':
        ngx_memcpy(dst, "&#61;", 5); return 5;
    case '`':
        ngx_memcpy(dst, "&#96;", 5); return 5;
    default:
        *dst = c;
        return 1;
    }
}

/* 计算 value HTML 转义后的长度 */
static size_t
ngx_http_auth_cookie_html_escape_len(ngx_str_t *value)
{
    size_t   i, len = 0;

    for (i = 0; i < value->len; i++) {
        switch (value->data[i]) {
        case '<': len += 4; break;
        case '>': len += 4; break;
        case '&': len += 5; break;
        case '"': len += 6; break;
        case '\'': len += 5; break;
        case '=': len += 5; break;
        case '`': len += 5; break;
        default: len += 1; break;
        }
    }
    return len;
}

/* 将 value HTML 转义后追加写入 dst,返回新指针 */
static u_char *
ngx_http_auth_cookie_html_escape_write(ngx_str_t *value, u_char *dst)
{
    size_t   i;

    for (i = 0; i < value->len; i++) {
        dst += ngx_http_auth_cookie_html_escape_char(value->data[i], dst);
    }
    return dst;
}

/*
 * 在 src 中把所有 token 替换为转义后的 value,结果写入 pool 分配的新缓冲。
 * 返回 NGX_OK 时 *out 指向结果。
 */
static ngx_int_t
ngx_http_auth_cookie_page_replace(ngx_pool_t *pool, ngx_str_t *src,
    const u_char *token, size_t token_len, ngx_str_t *value, ngx_str_t *out)
{
    u_char     *dst, *cur, *p;
    size_t      count, total, value_esc_len;

    /* 统计出现次数 */
    count = 0;
    cur = src->data;
    while (cur + token_len <= src->data + src->len) {
        if (ngx_memcmp(cur, token, token_len) == 0) {
            count++;
            cur += token_len;
        } else {
            cur++;
        }
    }

    if (count == 0) {
        *out = *src;
        return NGX_OK;
    }

    if (value->len > NGX_AUTH_COOKIE_PAGE_MAX / 6) {
        return NGX_ERROR;
    }

    value_esc_len = ngx_http_auth_cookie_html_escape_len(value);
    total = src->len - count * token_len;
    if (value_esc_len != 0
        && count > (NGX_AUTH_COOKIE_PAGE_MAX - total) / value_esc_len)
    {
        return NGX_ERROR;
    }
    total += count * value_esc_len;

    if (total > NGX_AUTH_COOKIE_PAGE_MAX) {
        return NGX_ERROR;
    }

    dst = ngx_pnalloc(pool, total);
    if (dst == NULL) {
        return NGX_ERROR;
    }

    cur = src->data;
    p = dst;
    while (cur < src->data + src->len) {
        if (cur + token_len <= src->data + src->len
            && ngx_strncmp(cur, token, token_len) == 0)
        {
            p = ngx_http_auth_cookie_html_escape_write(value, p);
            cur += token_len;
        } else {
            *p++ = *cur++;
        }
    }

    out->data = dst;
    out->len = p - dst;
    return NGX_OK;
}

/*
 * 渲染登录页:tpl 为模板(内置或外部文件),依次替换 title/error/next/action。
 * 返回 NGX_OK 时 *page 指向最终页面。
 */
ngx_int_t
ngx_http_auth_cookie_page_render(ngx_pool_t *pool, ngx_str_t *tpl,
    ngx_str_t *title, ngx_str_t *error, ngx_str_t *next, ngx_str_t *action,
    ngx_str_t *page)
{
    ngx_str_t   stage;
    ngx_int_t   rc;

    stage = *tpl;

    rc = ngx_http_auth_cookie_page_replace(pool, &stage,
              (u_char *) "{{title}}", sizeof("{{title}}") - 1, title, &stage);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_auth_cookie_page_replace(pool, &stage,
              (u_char *) "{{error}}", sizeof("{{error}}") - 1, error, &stage);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_auth_cookie_page_replace(pool, &stage,
              (u_char *) "{{action}}", sizeof("{{action}}") - 1, action,
              &stage);
    if (rc != NGX_OK) {
        return rc;
    }

    /* 用户可控的 next 最后替换,避免其内容被当作其他 token 再解释。 */
    rc = ngx_http_auth_cookie_page_replace(pool, &stage,
              (u_char *) "{{next}}", sizeof("{{next}}") - 1, next, &stage);
    if (rc != NGX_OK) {
        return rc;
    }

    *page = stage;
    return NGX_OK;
}
