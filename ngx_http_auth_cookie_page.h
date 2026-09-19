/*
 * ngx_http_auth_cookie_module — 登录页渲染
 *
 * auth_cookie_page 三态:
 *   basic   - 内置简洁登录页(默认)
 *   premium - 内置精美登录页
 *   /绝对路径.html - 使用外部 HTML 文件(自定义页面)
 *
 * 登录页为 HTML 表单,POST username/password 到登录 URI。
 * 自定义页面约定:替换占位符 {{title}}/{{error}}/{{next}}/{{action}}。
 */

#ifndef _NGX_HTTP_AUTH_COOKIE_PAGE_H_INCLUDED_
#define _NGX_HTTP_AUTH_COOKIE_PAGE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* 返回内置页面内容(basic/premium);未知返回 NULL */
const u_char *ngx_http_auth_cookie_builtin_page(ngx_str_t *page);

/* 配置阶段读取外部 HTML;成功返回 NGX_OK, *content 指向 pool 内存 */
ngx_int_t ngx_http_auth_cookie_load_page(ngx_pool_t *pool, ngx_log_t *log,
    ngx_str_t *path, ngx_str_t *content);

/*
 * 渲染登录页:单遍扫描 tpl(内置或外部文件),替换 title/error/next/action
 * 占位符(均做 HTML 转义)。替换值不会被再次扫描,其中文本不会被当作
 * 占位符解释。返回 NGX_OK 时 *page 指向最终页面(pool 内存)。
 */
ngx_int_t ngx_http_auth_cookie_page_render(ngx_pool_t *pool, ngx_str_t *tpl,
    ngx_str_t *title, ngx_str_t *error, ngx_str_t *next, ngx_str_t *action,
    ngx_str_t *page);

#endif /* _NGX_HTTP_AUTH_COOKIE_PAGE_H_INCLUDED_ */
