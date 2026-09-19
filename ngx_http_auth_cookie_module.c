/*
 * ngx_http_auth_cookie_module — 通过 HMAC 签名 cookie 会话认证
 *
 * 使用方式与 auth_basic 一致:在 server/location 声明 auth_cookie_user_file 即启用。
 * 登录后签发带签名的 cookie,每请求验签 + 校验过期即放行;无服务端会话表,
 * 天然支持多 worker、重启不丢会话(secret 持久化)。
 *
 * 配置项(server/location 上下文):
 *   auth_cookie_user_file <path>      htpasswd 用户文件;声明即启用认证
 *   auth_cookie_page <value>          登录页:basic(默认)/premium/绝对路径.html
 *   auth_cookie_name <str>            cookie 名,默认 auth_cookie
 *   auth_cookie_secure <on/off>       仅 HTTPS 下发 cookie,默认 on
 *   auth_cookie_secret <path>         HMAC 密钥文件,默认 /etc/nginx/auth_cookie.secret
 *   auth_cookie_session_ttl <time>    会话有效期,默认 12h
 *   auth_cookie_title <str>           登录页标题,可选
 *   auth_cookie_login_uri <uri>       登录页 URI,默认 /_login
 *   auth_cookie_logout_uri <uri>      登出 URI(POST 清 cookie),可选
 *   auth_cookie_login_rate <ip_n> <ip_time> <ip_username_n> <ip_username_time>
 *                                      IP/IP+用户名令牌桶,默认 10/1000ms + 1/1000ms,可 off
 *   auth_cookie_login_rate_key <mode>  限流键:ip/username/ip_username(默认)
 *   auth_cookie_login_rate_ip_header   可信代理提供的客户端 IP Header
 *   auth_cookie_login_rate_trusted_proxy 可信代理 IP/CIDR
 *   auth_cookie_login_rate_zone_size   http 级每个共享内存容量,默认 1m
 *
 * 流程:
 *   已登录(验签通过)     → 放行,设置 $auth_cookie_user
 *   登录 URI GET          → 渲染登录页
 *   登录 URI POST         → 校验 htpasswd,签发 cookie,302 回 next
 *   登出 URI POST         → 清除 cookie,302
 *   其他未认证请求        → 302 到登录 URI?next=原请求
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_crypt.h>

#include "ngx_http_auth_cookie_util.h"
#include "ngx_http_auth_cookie_crypto.h"
#include "ngx_http_auth_cookie_htpasswd.h"
#include "ngx_http_auth_cookie_page.h"
#include "ngx_http_auth_cookie_rate_limit.h"

#define NGX_AUTH_COOKIE_DEFAULT_NAME       "auth_cookie"
#define NGX_AUTH_COOKIE_DEFAULT_SECRET     "/etc/nginx/auth_cookie.secret"
#define NGX_AUTH_COOKIE_DEFAULT_TTL        43200  /* 12h */
#define NGX_AUTH_COOKIE_DEFAULT_LOGIN_URI  "/_login"
#define NGX_AUTH_COOKIE_MAX_FORM_SIZE      8192

static ngx_str_t ngx_http_auth_cookie_default_page = ngx_string("basic");
static ngx_str_t ngx_http_auth_cookie_default_secret =
    ngx_string(NGX_AUTH_COOKIE_DEFAULT_SECRET);
static ngx_str_t ngx_http_auth_cookie_default_login_uri =
    ngx_string(NGX_AUTH_COOKIE_DEFAULT_LOGIN_URI);

/* 每次请求认证上下文:存放解出的用户名(供 $auth_cookie_user 变量) */
typedef struct {
    ngx_str_t   user;
    ngx_flag_t  authed;
} ngx_http_auth_cookie_ctx_t;

typedef struct {
    ngx_str_t   *user_file;
    ngx_str_t   *page;
    ngx_str_t    cookie_name;
    ngx_flag_t   secure;
    ngx_str_t   *secret_file;
    time_t       session_ttl;
    ngx_str_t   *title;
    ngx_str_t   *login_uri;
    ngx_str_t   *logout_uri;
    ngx_str_t    secret;      /* HMAC 密钥,配置阶段载入 */
    ngx_array_t *users;       /* 配置阶段载入的 htpasswd 用户表 */
    ngx_str_t    page_tpl;    /* 自定义登录页,配置阶段载入 */
    ngx_flag_t   enabled;
    ngx_flag_t   csrf;        /* 登录/登出 POST 的同源校验开关 */
    ngx_http_auth_cookie_rate_loc_conf_t rate;
} ngx_http_auth_cookie_loc_conf_t;


static ngx_int_t ngx_http_auth_cookie_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_cookie_init(ngx_conf_t *cf);
static void *ngx_http_auth_cookie_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_auth_cookie_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_cookie_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static char *ngx_http_auth_cookie_user_file(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_auth_cookie_str_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_auth_cookie_page_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_auth_cookie_rate_scope_init(ngx_conf_t *cf,
    ngx_http_auth_cookie_loc_conf_t *conf);
static ngx_int_t ngx_http_auth_cookie_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_auth_cookie_user_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

/* 登录/登出流程 */
static ngx_int_t ngx_http_auth_cookie_endpoint_handler(ngx_http_request_t *r);
static void ngx_http_auth_cookie_login_body_handler(ngx_http_request_t *r);
static void ngx_http_auth_cookie_logout_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_cookie_serve_login_page(ngx_http_request_t *r,
    ngx_http_auth_cookie_loc_conf_t *alcf, ngx_str_t *next, ngx_str_t *error,
    ngx_uint_t status);
static ngx_int_t ngx_http_auth_cookie_rate_limited(ngx_http_request_t *r,
    ngx_http_auth_cookie_loc_conf_t *alcf, ngx_str_t *next);
static ngx_int_t ngx_http_auth_cookie_rate_body_check(ngx_http_request_t *r,
    ngx_http_auth_cookie_loc_conf_t *alcf, ngx_str_t *username,
    ngx_str_t *next);
static ngx_int_t ngx_http_auth_cookie_set_cookie(ngx_http_request_t *r,
    ngx_http_auth_cookie_loc_conf_t *alcf, ngx_str_t *value, time_t max_age);
static ngx_int_t ngx_http_auth_cookie_send_redirect(ngx_http_request_t *r,
    ngx_str_t *location);
static ngx_int_t ngx_http_auth_cookie_build_redirect_uri(ngx_http_request_t *r,
    ngx_http_auth_cookie_loc_conf_t *alcf, ngx_str_t *out);

/* 工具 */
static ngx_int_t ngx_http_auth_cookie_uri_equal(ngx_http_request_t *r,
    ngx_str_t *uri);
static ngx_int_t ngx_http_auth_cookie_get_next(ngx_http_request_t *r,
    ngx_str_t *next);
static ngx_int_t ngx_http_auth_cookie_get_cookie(ngx_http_request_t *r,
    ngx_str_t *name, ngx_str_t *value);
static ngx_int_t ngx_http_auth_cookie_page_template(ngx_http_request_t *r,
    ngx_http_auth_cookie_loc_conf_t *alcf, ngx_str_t *tpl);
static ngx_int_t ngx_http_auth_cookie_valid_uri(ngx_str_t *uri);
static ngx_int_t ngx_http_auth_cookie_valid_name(ngx_str_t *name);
static ngx_int_t ngx_http_auth_cookie_form_too_large(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_cookie_check_csrf(ngx_http_request_t *r,
    ngx_http_auth_cookie_loc_conf_t *alcf);
static ngx_table_elt_t *ngx_http_auth_cookie_find_header(ngx_http_request_t *r,
    ngx_str_t *name);
static ngx_int_t ngx_http_auth_cookie_add_header(ngx_http_request_t *r,
    ngx_str_t *key, ngx_str_t *value);


static ngx_command_t  ngx_http_auth_cookie_commands[] = {

    { ngx_string("auth_cookie_user_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_auth_cookie_user_file,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_cookie_loc_conf_t, user_file),
      NULL },

    { ngx_string("auth_cookie_page"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_auth_cookie_page_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_cookie_loc_conf_t, page),
      NULL },

    { ngx_string("auth_cookie_name"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_cookie_loc_conf_t, cookie_name),
      NULL },

    { ngx_string("auth_cookie_secure"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_cookie_loc_conf_t, secure),
      NULL },

    { ngx_string("auth_cookie_csrf"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_cookie_loc_conf_t, csrf),
      NULL },

    { ngx_string("auth_cookie_secret"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_auth_cookie_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_cookie_loc_conf_t, secret_file),
      NULL },

    { ngx_string("auth_cookie_session_ttl"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_cookie_loc_conf_t, session_ttl),
      NULL },

    { ngx_string("auth_cookie_title"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_auth_cookie_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_cookie_loc_conf_t, title),
      NULL },

    { ngx_string("auth_cookie_login_uri"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_auth_cookie_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_cookie_loc_conf_t, login_uri),
      NULL },

    { ngx_string("auth_cookie_logout_uri"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_auth_cookie_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_cookie_loc_conf_t, logout_uri),
      NULL },

    { ngx_string("auth_cookie_login_rate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1|NGX_CONF_TAKE4,
      ngx_http_auth_cookie_login_rate_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_cookie_loc_conf_t, rate),
      NULL },

    { ngx_string("auth_cookie_login_rate_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_auth_cookie_login_rate_key_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_cookie_loc_conf_t, rate),
      NULL },

    { ngx_string("auth_cookie_login_rate_ip_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_1MORE,
      ngx_http_auth_cookie_login_rate_ip_header_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_cookie_loc_conf_t, rate),
      NULL },

    { ngx_string("auth_cookie_login_rate_trusted_proxy"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_1MORE,
      ngx_http_auth_cookie_login_rate_trusted_proxy_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_cookie_loc_conf_t, rate),
      NULL },

    { ngx_string("auth_cookie_login_rate_zone_size"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_auth_cookie_login_rate_zone_size_set,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_variable_t  ngx_http_auth_cookie_vars[] = {

    { ngx_string("auth_cookie_user"), NULL,
      ngx_http_auth_cookie_user_variable, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

      ngx_http_null_variable
};


static ngx_http_module_t  ngx_http_auth_cookie_module_ctx = {
    ngx_http_auth_cookie_add_variables,    /* preconfiguration */
    ngx_http_auth_cookie_init,             /* postconfiguration */

    ngx_http_auth_cookie_create_main_conf, /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_auth_cookie_create_loc_conf,  /* create location configuration */
    ngx_http_auth_cookie_merge_loc_conf    /* merge location configuration */
};


ngx_module_t  ngx_http_auth_cookie_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_cookie_module_ctx,      /* module context */
    ngx_http_auth_cookie_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_auth_cookie_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_auth_cookie_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }
        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_http_auth_cookie_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_auth_cookie_rate_main_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf == NULL) {
        return NULL;
    }
    conf->zone_size = NGX_CONF_UNSET_SIZE;
    return conf;
}


static ngx_int_t
ngx_http_auth_cookie_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_auth_cookie_rate_main_conf_t *amcf;

    amcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_auth_cookie_module);
    if (ngx_http_auth_cookie_rate_zone_create(cf, amcf) != NGX_OK) {
        return NGX_ERROR;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    /* 与 auth_basic 相同:追加到 access 数组末尾,引擎逆序后本模块先于 IP ACL。 */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_cookie_handler;

    return NGX_OK;
}


static void *
ngx_http_auth_cookie_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_cookie_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_cookie_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->user_file = NGX_CONF_UNSET_PTR;
    conf->page = NGX_CONF_UNSET_PTR;
    conf->secret_file = NGX_CONF_UNSET_PTR;
    conf->title = NGX_CONF_UNSET_PTR;
    conf->login_uri = NGX_CONF_UNSET_PTR;
    conf->logout_uri = NGX_CONF_UNSET_PTR;
    conf->session_ttl = NGX_CONF_UNSET;
    conf->secure = NGX_CONF_UNSET;
    conf->csrf = NGX_CONF_UNSET;
    conf->enabled = NGX_CONF_UNSET;
    conf->cookie_name.len = 0;
    conf->cookie_name.data = NULL;
    ngx_http_auth_cookie_rate_create_loc_conf(&conf->rate);

    return conf;
}


static char *
ngx_http_auth_cookie_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_cookie_loc_conf_t  *prev = parent;
    ngx_http_auth_cookie_loc_conf_t  *conf = child;

    ngx_conf_merge_ptr_value(conf->user_file, prev->user_file, NULL);
    ngx_conf_merge_ptr_value(conf->page, prev->page,
                             &ngx_http_auth_cookie_default_page);
    ngx_conf_merge_ptr_value(conf->secret_file, prev->secret_file,
                             &ngx_http_auth_cookie_default_secret);
    ngx_conf_merge_ptr_value(conf->title, prev->title, NULL);
    ngx_conf_merge_ptr_value(conf->login_uri, prev->login_uri,
                             &ngx_http_auth_cookie_default_login_uri);
    ngx_conf_merge_ptr_value(conf->logout_uri, prev->logout_uri, NULL);

    /* 归一:UNSET_PTR(父子均未设置)统一为 NULL,便于运行时判断 */
    if (conf->user_file == NGX_CONF_UNSET_PTR) {
        conf->user_file = NULL;
    }
    if (conf->title == NGX_CONF_UNSET_PTR) {
        conf->title = NULL;
    }
    if (conf->logout_uri == NGX_CONF_UNSET_PTR) {
        conf->logout_uri = NULL;
    }

    ngx_conf_merge_str_value(conf->cookie_name, prev->cookie_name,
                             NGX_AUTH_COOKIE_DEFAULT_NAME);

    ngx_conf_merge_sec_value(conf->session_ttl, prev->session_ttl,
                             NGX_AUTH_COOKIE_DEFAULT_TTL);

    ngx_conf_merge_value(conf->secure, prev->secure, 1);

    /* CSRF 同源校验默认开启,可用 auth_cookie_csrf off 关闭 */
    ngx_conf_merge_value(conf->csrf, prev->csrf, 1);

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);

    if (ngx_http_auth_cookie_rate_merge_loc_conf(cf, &prev->rate, &conf->rate)
        != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (conf->enabled && conf->rate.rate != NULL
        && ngx_http_auth_cookie_rate_scope_init(cf, conf) != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_auth_cookie_valid_uri(conf->login_uri) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_cookie_login_uri must be a safe absolute URI");
        return NGX_CONF_ERROR;
    }

    if (conf->logout_uri != NULL
        && ngx_http_auth_cookie_valid_uri(conf->logout_uri) != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_cookie_logout_uri must be a safe absolute URI");
        return NGX_CONF_ERROR;
    }

    if (conf->logout_uri != NULL
        && conf->logout_uri->len == conf->login_uri->len
        && ngx_strncmp(conf->logout_uri->data, conf->login_uri->data,
                       conf->login_uri->len) == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_cookie login and logout URI must differ");
        return NGX_CONF_ERROR;
    }

    if (ngx_http_auth_cookie_valid_name(&conf->cookie_name) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_cookie_name is not a valid cookie name");
        return NGX_CONF_ERROR;
    }

    if (conf->session_ttl <= 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_cookie_session_ttl must be greater than zero");
        return NGX_CONF_ERROR;
    }

    /* 在 master 配置阶段载入 secret 与用户表,所有 worker fork 后共享同一份。 */
    if (conf->enabled) {
        if (ngx_http_auth_cookie_load_secret(cf->pool, cf->log,
                                             conf->secret_file,
                                             &conf->secret)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        if (ngx_http_auth_cookie_load_users(cf->pool, cf->log,
                                            conf->user_file, &conf->users)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        if (conf->page != NULL && conf->page->len > 1
            && conf->page->data[0] == '/')
        {
            if (ngx_http_auth_cookie_load_page(cf->pool, cf->log, conf->page,
                                               &conf->page_tpl)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_auth_cookie_rate_scope_init(ngx_conf_t *cf,
    ngx_http_auth_cookie_loc_conf_t *conf)
{
    static ngx_str_t headers_mode = ngx_string("headers");
    static ngx_str_t auto_mode = ngx_string("auto");
    ngx_http_core_srv_conf_t *cscf;
    ngx_str_t parts[7];
    u_char line[NGX_INT_T_LEN];

    cscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);

    parts[0] = *conf->user_file;
    parts[1] = *conf->secret_file;
    parts[2] = *conf->login_uri;
    parts[3] = conf->cookie_name;
    parts[4].data = (cscf != NULL && cscf->file_name != NULL)
        ? cscf->file_name : (u_char *) "";
    parts[4].len = parts[4].data != NULL ? ngx_strlen(parts[4].data) : 0;
    parts[5].data = line;
    parts[5].len = cscf != NULL
        ? (size_t) (ngx_sprintf(line, "%ui", cscf->line) - line) : 0;
    parts[6] = conf->rate.ip_headers != NULL && conf->rate.ip_headers->nelts != 0
        ? headers_mode : auto_mode;

    if (ngx_http_auth_cookie_rate_scope(cf->pool, parts, 7,
                                        conf->rate.scope)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    conf->rate.scope_ready = 1;
    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_auth_cookie_valid_uri(ngx_str_t *uri)
{
    size_t  i;

    if (uri->len == 0 || uri->data[0] != '/'
        || (uri->len > 1 && uri->data[1] == '/'))
    {
        return NGX_ERROR;
    }

    for (i = 0; i < uri->len; i++) {
        if (uri->data[i] <= 0x20 || uri->data[i] == 0x7f
            || uri->data[i] == '\\' || uri->data[i] == '?'
            || uri->data[i] == '#')
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_cookie_form_too_large(ngx_http_request_t *r)
{
    /* chunked 或未知长度在读 body 前拒绝,与 Content-Length 共用 8KB 上限。 */
    if (r->headers_in.chunked
        || r->headers_in.content_length_n < 0
        || r->headers_in.content_length_n > NGX_AUTH_COOKIE_MAX_FORM_SIZE)
    {
        return 1;
    }

    return 0;
}


/*
 * 在请求头链表中按名字查找(不区分大小写),未找到返回 NULL。
 */
static ngx_table_elt_t *
ngx_http_auth_cookie_find_header(ngx_http_request_t *r, ngx_str_t *name)
{
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;
    ngx_uint_t        i;

    part = &r->headers_in.headers.part;
    h = part->elts;

    for ( ;; ) {
        for (i = 0; i < part->nelts; i++) {
            if (h[i].key.len == name->len
                && ngx_strncasecmp(h[i].key.data, name->data, name->len) == 0)
            {
                return &h[i];
            }
        }

        if (part->next == NULL) {
            break;
        }

        part = part->next;
        h = part->elts;
    }

    return NULL;
}


/*
 * 登录/登出 POST 的同源校验(CSRF 防护):
 * - 存在 Origin 时,其 host:port 必须与请求 Host 一致(忽略 scheme,
 *   以兼容 TLS 终结代理后端的 scheme 差异);Origin: null 视为不匹配。
 * - 缺失 Origin 时,Sec-Fetch-Site: cross-site 拒绝。
 * - 两者都缺失(非浏览器客户端)放行。
 */
static ngx_int_t
ngx_http_auth_cookie_check_csrf(ngx_http_request_t *r,
    ngx_http_auth_cookie_loc_conf_t *alcf)
{
    ngx_table_elt_t  *origin, *fetch_site;
    ngx_str_t         name, host, authority;
    u_char           *p, *last;

    if (!alcf->csrf) {
        return NGX_OK;
    }

    ngx_str_set(&name, "Origin");
    origin = ngx_http_auth_cookie_find_header(r, &name);

    if (origin == NULL) {
        ngx_str_set(&name, "Sec-Fetch-Site");
        fetch_site = ngx_http_auth_cookie_find_header(r, &name);

        if (fetch_site != NULL
            && fetch_site->value.len == sizeof("cross-site") - 1
            && ngx_strncasecmp(fetch_site->value.data, (u_char *) "cross-site",
                               sizeof("cross-site") - 1)
               == 0)
        {
            return NGX_HTTP_BAD_REQUEST;
        }

        return NGX_OK;
    }

    /* Origin = scheme "://" authority ["/" ...];取 authority 部分 */
    p = origin->value.data;
    last = origin->value.data + origin->value.len;

    while (p < last && *p != ':') {
        p++;
    }
    if (p == last || last - p < 3 || p[1] != '/' || p[2] != '/') {
        return NGX_HTTP_BAD_REQUEST;
    }
    p += 3;

    authority.data = p;
    while (p < last && *p != '/') {
        p++;
    }
    authority.len = p - authority.data;

    if (r->headers_in.host != NULL) {
        host = r->headers_in.host->value;
    } else {
        host = r->headers_in.server;
    }

    if (authority.len == 0 || authority.len != host.len
        || ngx_strncasecmp(authority.data, host.data, host.len) != 0)
    {
        return NGX_HTTP_BAD_REQUEST;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_cookie_add_header(ngx_http_request_t *r, ngx_str_t *key,
    ngx_str_t *value)
{
    ngx_table_elt_t  *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
#if (nginx_version >= 1023000)
    h->next = NULL;
#endif
    h->key = *key;
    h->value = *value;

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_cookie_valid_name(ngx_str_t *name)
{
    size_t  i;
    u_char  c;

    if (name->len == 0) {
        return NGX_ERROR;
    }

    for (i = 0; i < name->len; i++) {
        c = name->data[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9')
            || c == '!' || c == '#' || c == '$' || c == '%'
            || c == '&' || c == '\'' || c == '*' || c == '+'
            || c == '-' || c == '.' || c == '^' || c == '_'
            || c == '`' || c == '|' || c == '~')
        {
            continue;
        }
        return NGX_ERROR;
    }

    return NGX_OK;
}


static char *
ngx_http_auth_cookie_user_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_cookie_loc_conf_t        *alcf = conf;
    ngx_http_auth_cookie_rate_main_conf_t  *amcf;
    ngx_str_t                              *value, *copy;

    if (alcf->enabled != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (value[1].len == sizeof("off") - 1
        && ngx_strncmp(value[1].data, "off", sizeof("off") - 1) == 0)
    {
        alcf->user_file = NULL;
        alcf->enabled = 0;
        return NGX_CONF_OK;
    }

    /* 复制到配置池,避免引用指令解析期的临时内存(cf->args 之后会被复用) */
    copy = ngx_palloc(cf->pool, sizeof(ngx_str_t));
    if (copy == NULL) {
        return NGX_CONF_ERROR;
    }
    copy->len = value[1].len;
    copy->data = ngx_pnalloc(cf->pool, value[1].len + 1);
    if (copy->data == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(copy->data, value[1].data, value[1].len);
    copy->data[value[1].len] = '\0';

    alcf->user_file = copy;
    alcf->enabled = 1;

    amcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_auth_cookie_module);
    amcf->auth_used = 1;

    return NGX_CONF_OK;
}


/*
 * 通用字符串指令 setter:字段类型为 ngx_str_t*。
 * 值复制到配置池,避免引用指令解析期的临时内存。
 */
static char *
ngx_http_auth_cookie_str_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char        *p = conf;
    ngx_str_t  **field, *value, *copy;

    field = (ngx_str_t **) (p + cmd->offset);

    if (*field != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    copy = ngx_palloc(cf->pool, sizeof(ngx_str_t));
    if (copy == NULL) {
        return NGX_CONF_ERROR;
    }
    copy->len = value[1].len;
    copy->data = ngx_pnalloc(cf->pool, value[1].len + 1);
    if (copy->data == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(copy->data, value[1].data, value[1].len);
    copy->data[value[1].len] = '\0';

    *field = copy;

    return NGX_CONF_OK;
}


static char *
ngx_http_auth_cookie_page_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char        *rc, *p = conf;
    ngx_str_t  **field;

    rc = ngx_http_auth_cookie_str_slot(cf, cmd, conf);
    if (rc != NGX_CONF_OK) {
        return rc;
    }

    field = (ngx_str_t **) (p + cmd->offset);

    if (((*field)->len == sizeof("basic") - 1
         && ngx_strncmp((*field)->data, "basic", sizeof("basic") - 1) == 0)
        || ((*field)->len == sizeof("premium") - 1
            && ngx_strncmp((*field)->data, "premium",
                           sizeof("premium") - 1) == 0)
        || ((*field)->len > 1 && (*field)->data[0] == '/'))
    {
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "auth_cookie_page must be basic, premium, or an absolute path");
    return NGX_CONF_ERROR;
}


static ngx_int_t
ngx_http_auth_cookie_user_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_auth_cookie_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_cookie_module);

    if (ctx == NULL || !ctx->authed) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = ctx->user.len;
    v->data = ctx->user.data;

    return NGX_OK;
}


/*
 * 判断请求 URI 是否等于给定 uri(仅比较 pathname)
 */
static ngx_int_t
ngx_http_auth_cookie_uri_equal(ngx_http_request_t *r, ngx_str_t *uri)
{
    if (uri == NULL) {
        return NGX_DECLINED;
    }

    if (r->uri.len != uri->len) {
        return NGX_DECLINED;
    }

    if (ngx_strncmp(r->uri.data, uri->data, uri->len) == 0) {
        return NGX_OK;
    }

    return NGX_DECLINED;
}


/*
 * 从 query string 取 next 参数并做开放重定向防护
 */
static ngx_int_t
ngx_http_auth_cookie_get_next(ngx_http_request_t *r, ngx_str_t *next)
{
    next->len = 0;
    next->data = NULL;

    if (ngx_http_arg(r, (u_char *) "next", sizeof("next") - 1, next)
        != NGX_OK)
    {
        return NGX_OK;
    }

    {
        ngx_str_t  decoded;

        if (ngx_http_auth_cookie_unescape(r->pool, next, &decoded) != NGX_OK) {
            next->len = 0;
            return NGX_OK;
        }
        *next = decoded;
    }

    ngx_http_auth_cookie_sanitize_next(r, next);

    return NGX_OK;
}


/* nginx 1.23 起将重复请求头从数组改为链表。 */
static ngx_int_t
ngx_http_auth_cookie_get_cookie(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *value)
{
#if (nginx_version >= 1023000)
    if (r->headers_in.cookie != NULL
        && ngx_http_parse_multi_header_lines(r, r->headers_in.cookie,
                                             name, value)
           != NULL)
    {
        return NGX_OK;
    }
#else
    if (r->headers_in.cookies.nelts != 0
        && ngx_http_parse_multi_header_lines(&r->headers_in.cookies,
                                             name, value)
           != NGX_DECLINED)
    {
        return NGX_OK;
    }
#endif

    return NGX_DECLINED;
}


/*
 * 设置 Set-Cookie 响应头
 * max_age == 0 表示删除 cookie
 */
static ngx_int_t
ngx_http_auth_cookie_set_cookie(ngx_http_request_t *r,
    ngx_http_auth_cookie_loc_conf_t *alcf, ngx_str_t *value, time_t max_age)
{
    u_char          *p, *buf;
    size_t           len;
    ngx_table_elt_t *sc;

    len = alcf->cookie_name.len + 1 + value->len
          + sizeof("; Path=/; HttpOnly; SameSite=Lax") - 1;
    if (alcf->secure) {
        len += sizeof("; Secure") - 1;
    }

    if (max_age == 0) {
        len += sizeof("; Max-Age=0") - 1;
    } else {
        /* time_t 十进制最长 20 位(+ 可能负号),用固定 21 预算 */
        len += sizeof("; Max-Age=") - 1 + 21;
    }

    buf = ngx_pnalloc(r->pool, len);
    if (buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_cpymem(buf, alcf->cookie_name.data, alcf->cookie_name.len);
    *p++ = '=';
    p = ngx_cpymem(p, value->data, value->len);
    p = ngx_cpymem(p, "; Path=/", sizeof("; Path=/") - 1);

    if (max_age == 0) {
        p = ngx_cpymem(p, "; Max-Age=0", sizeof("; Max-Age=0") - 1);
    } else {
        p = ngx_cpymem(p, "; Max-Age=", sizeof("; Max-Age=") - 1);
        p = ngx_sprintf(p, "%T", max_age);
    }

    p = ngx_cpymem(p, "; HttpOnly; SameSite=Lax",
                   sizeof("; HttpOnly; SameSite=Lax") - 1);

    if (alcf->secure) {
        p = ngx_cpymem(p, "; Secure", sizeof("; Secure") - 1);
    }

    sc = ngx_list_push(&r->headers_out.headers);
    if (sc == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    sc->hash = 1;
#if (nginx_version >= 1023000)
    sc->next = NULL;
#endif
    ngx_str_set(&sc->key, "Set-Cookie");
    sc->value.data = buf;
    sc->value.len = p - buf;

    return NGX_OK;
}


/*
 * 302 重定向
 */
static ngx_int_t
ngx_http_auth_cookie_send_redirect(ngx_http_request_t *r, ngx_str_t *location)
{
    size_t  i;

    /* HTTP/1 header filter 会原样输出 Location,此处做最终防御。 */
    for (i = 0; i < location->len; i++) {
        if (location->data[i] <= 0x1f || location->data[i] == 0x7f) {
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    r->headers_out.location = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.location == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.location->hash = 1;
#if (nginx_version >= 1023000)
    r->headers_out.location->next = NULL;
#endif
    ngx_str_set(&r->headers_out.location->key, "Location");
    r->headers_out.location->value = *location;

    return NGX_HTTP_MOVED_TEMPORARILY;
}


/*
 * 选择登录页模板(basic/premium/外部文件)
 */
static ngx_int_t
ngx_http_auth_cookie_page_template(ngx_http_request_t *r,
    ngx_http_auth_cookie_loc_conf_t *alcf, ngx_str_t *tpl)
{
    ngx_str_t        page;
    const u_char    *builtin;

    if (alcf->page != NULL && alcf->page->len > 0) {
        if (alcf->page->data[0] == '/') {
            if (alcf->page_tpl.len == 0) {
                return NGX_ERROR;
            }
            *tpl = alcf->page_tpl;
            return NGX_OK;
        } else {
            builtin = ngx_http_auth_cookie_builtin_page(alcf->page);
            if (builtin != NULL) {
                tpl->data = (u_char *) builtin;
                tpl->len = ngx_strlen(builtin);
                return NGX_OK;
            }
            return NGX_ERROR;
        }
    }

    /* 默认 basic */
    page.data = (u_char *) "basic";
    page.len = sizeof("basic") - 1;
    builtin = ngx_http_auth_cookie_builtin_page(&page);
    tpl->data = (u_char *) builtin;
    tpl->len = ngx_strlen(builtin);

    return NGX_OK;
}


/*
 * 渲染并发送登录页
 */
static ngx_int_t
ngx_http_auth_cookie_serve_login_page(ngx_http_request_t *r,
    ngx_http_auth_cookie_loc_conf_t *alcf, ngx_str_t *next, ngx_str_t *error,
    ngx_uint_t status)
{
    ngx_str_t   title, action, page, tpl;
    ngx_buf_t  *b;
    ngx_chain_t out;
    ngx_str_t   hkey, hval;
    ngx_int_t   rc;

    if (alcf->title != NULL && alcf->title->len > 0) {
        title = *alcf->title;
    } else {
        ngx_str_set(&title, "登录");
    }

    if (alcf->login_uri != NULL) {
        action = *alcf->login_uri;
    } else {
        ngx_str_set(&action, NGX_AUTH_COOKIE_DEFAULT_LOGIN_URI);
    }

    if (ngx_http_auth_cookie_page_template(r, alcf, &tpl) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_auth_cookie_page_render(r->pool, &tpl, &title, error, next,
                                         &action, &page)
        != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* 渲染结果在请求池内,直接按内存 buf 发送,不再复制一份。 */
    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    b->pos = page.data;
    b->last = page.data + page.len;
    b->memory = 1;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    r->headers_out.status = status;
    r->headers_out.content_length_n = page.len;
    ngx_str_set(&r->headers_out.content_type, "text/html; charset=utf-8");
    r->headers_out.content_type_len = r->headers_out.content_type.len;
    r->headers_out.content_type_lowcase = NULL;

    ngx_str_set(&hkey, "Cache-Control");
    ngx_str_set(&hval, "no-store");
    if (ngx_http_auth_cookie_add_header(r, &hkey, &hval) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_str_set(&hkey, "X-Frame-Options");
    ngx_str_set(&hval, "DENY");
    if (ngx_http_auth_cookie_add_header(r, &hkey, &hval) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_str_set(&hkey, "X-Content-Type-Options");
    ngx_str_set(&hval, "nosniff");
    if (ngx_http_auth_cookie_add_header(r, &hkey, &hval) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


static ngx_int_t
ngx_http_auth_cookie_rate_limited(ngx_http_request_t *r,
    ngx_http_auth_cookie_loc_conf_t *alcf, ngx_str_t *next)
{
    ngx_str_t error;

    ngx_str_set(&error, "请求过于频繁，请稍后重试");
    return ngx_http_auth_cookie_serve_login_page(r, alcf, next, &error,
                                                 NGX_HTTP_TOO_MANY_REQUESTS);
}


/* body 回调内统一完成非 OK 结果的 finalize，调用方直接返回。 */
static ngx_int_t
ngx_http_auth_cookie_rate_body_check(ngx_http_request_t *r,
    ngx_http_auth_cookie_loc_conf_t *alcf, ngx_str_t *username,
    ngx_str_t *next)
{
    ngx_int_t rc;

    rc = ngx_http_auth_cookie_rate_check(r, &alcf->rate, username);
    if (rc == NGX_AUTH_COOKIE_RATE_ALLOWED) {
        return NGX_OK;
    }
    if (rc == NGX_AUTH_COOKIE_RATE_DENIED) {
        rc = ngx_http_auth_cookie_rate_limited(r, alcf, next);
    } else if (rc == NGX_AUTH_COOKIE_RATE_BAD_IP) {
        rc = NGX_HTTP_BAD_REQUEST;
    } else {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_http_finalize_request(r, rc);
    return NGX_DONE;
}


/*
 * 登出 body 回调:清除 cookie 并重定向
 */
static void
ngx_http_auth_cookie_logout_body_handler(ngx_http_request_t *r)
{
    ngx_http_auth_cookie_loc_conf_t  *alcf;
    ngx_str_t                         empty, location, next;
    ngx_int_t                         rc;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_cookie_module);

    empty.len = 0;
    empty.data = (u_char *) "";

    rc = ngx_http_auth_cookie_set_cookie(r, alcf, &empty, 0);
    if (rc != NGX_OK) {
        ngx_http_finalize_request(r, rc);
        return;
    }

    ngx_http_auth_cookie_get_next(r, &next);
    if (next.len > 0) {
        location = next;
    } else if (alcf->login_uri != NULL) {
        location = *alcf->login_uri;
    } else {
        ngx_str_set(&location, NGX_AUTH_COOKIE_DEFAULT_LOGIN_URI);
    }

    rc = ngx_http_auth_cookie_send_redirect(r, &location);
    ngx_http_finalize_request(r, rc);
}


/*
 * 登录 POST body 回调:解析表单,校验用户,签发 cookie,重定向
 */
static void
ngx_http_auth_cookie_login_body_handler(ngx_http_request_t *r)
{
    ngx_http_auth_cookie_loc_conf_t  *alcf;
    ngx_chain_t                      *cl;
    ngx_buf_t                        *b;
    ngx_str_t                         body, username, password, next, cookie;
    ngx_str_t                         decoded, location, error;
    ngx_http_auth_cookie_user_t      *entry;
    ngx_int_t                         rc;
    ssize_t                           n;
    size_t                            i, part;
    u_char                           *p, *q, *end, *dst;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_cookie_module);
    ngx_str_null(&next);

    if (r->request_body == NULL) {
        if (alcf->rate.key_mode != NGX_AUTH_COOKIE_RATE_KEY_IP
            && ngx_http_auth_cookie_rate_body_check(r, alcf, NULL, &next)
               != NGX_OK)
        {
            return;
        }
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return;
    }

    body.len = 0;
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        b = cl->buf;
        if (b->in_file) {
            part = (size_t) (b->file_last - b->file_pos);
        } else {
            part = (size_t) (b->last - b->pos);
        }
        if (part > NGX_AUTH_COOKIE_MAX_FORM_SIZE - body.len) {
            if (alcf->rate.key_mode != NGX_AUTH_COOKIE_RATE_KEY_IP
                && ngx_http_auth_cookie_rate_body_check(r, alcf, NULL, &next)
                   != NGX_OK)
            {
                return;
            }
            ngx_http_finalize_request(r, NGX_HTTP_REQUEST_ENTITY_TOO_LARGE);
            return;
        }
        body.len += part;
    }

    if (body.len == 0) {
        if (alcf->rate.key_mode != NGX_AUTH_COOKIE_RATE_KEY_IP
            && ngx_http_auth_cookie_rate_body_check(r, alcf, NULL, &next)
               != NGX_OK)
        {
            return;
        }
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return;
    }

    body.data = ngx_pnalloc(r->pool, body.len);
    if (body.data == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    dst = body.data;
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        b = cl->buf;
        if (b->in_file) {
            part = (size_t) (b->file_last - b->file_pos);
            n = ngx_read_file(b->file, dst, part, b->file_pos);
            if (n != (ssize_t) part) {
                if (alcf->rate.key_mode != NGX_AUTH_COOKIE_RATE_KEY_IP
                    && ngx_http_auth_cookie_rate_body_check(r, alcf, NULL, &next)
                       != NGX_OK)
                {
                    return;
                }
                ngx_http_finalize_request(r,
                                          NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
            dst += part;
        } else {
            dst = ngx_cpymem(dst, b->pos, b->last - b->pos);
        }
    }

    /* 解析 username/password/next */
    username.len = 0;
    username.data = NULL;
    password.len = 0;
    password.data = NULL;
    next.len = 0;
    next.data = NULL;

    end = body.data + body.len;
    p = body.data;
    while (p < end) {
        q = ngx_strlchr(p, end, '&');
        if (q == NULL) {
            q = end;
        }

        if (q - p >= (ssize_t) sizeof("username=") - 1
            && ngx_strncmp(p, "username=", sizeof("username=") - 1) == 0)
        {
            username.data = p + sizeof("username=") - 1;
            username.len = q - username.data;
        } else if (q - p >= (ssize_t) sizeof("password=") - 1
                   && ngx_strncmp(p, "password=", sizeof("password=") - 1) == 0)
        {
            password.data = p + sizeof("password=") - 1;
            password.len = q - password.data;
        } else if (q - p >= (ssize_t) sizeof("next=") - 1
                   && ngx_strncmp(p, "next=", sizeof("next=") - 1) == 0)
        {
            next.data = p + sizeof("next=") - 1;
            next.len = q - next.data;
        }

        if (q == end) {
            break;
        }
        p = q + 1;
    }

    /* next 主要来自表单 hidden 字段;没有时兼容 query string。 */
    if (next.len > 0) {
        if (ngx_http_auth_cookie_unescape(r->pool, &next, &decoded) != NGX_OK) {
            ngx_str_null(&next);
        } else {
            next = decoded;
            ngx_http_auth_cookie_sanitize_next(r, &next);
        }
    } else {
        ngx_http_auth_cookie_get_next(r, &next);
    }

    if (username.len == 0 || password.len == 0) {
        ngx_explicit_memzero(body.data, body.len);
        if (alcf->rate.key_mode != NGX_AUTH_COOKIE_RATE_KEY_IP
            && ngx_http_auth_cookie_rate_body_check(r, alcf, NULL, &next)
               != NGX_OK)
        {
            return;
        }
        ngx_str_set(&error, "请输入用户名和密码");
        rc = ngx_http_auth_cookie_serve_login_page(r, alcf, &next, &error, NGX_HTTP_OK);
        ngx_http_finalize_request(r, rc);
        return;
    }

    /* URL 解码用户名与密码 */
    if (ngx_http_auth_cookie_unescape(r->pool, &username, &decoded) != NGX_OK) {
        ngx_explicit_memzero(body.data, body.len);
        if (alcf->rate.key_mode != NGX_AUTH_COOKIE_RATE_KEY_IP
            && ngx_http_auth_cookie_rate_body_check(r, alcf, NULL, &next)
               != NGX_OK)
        {
            return;
        }
        ngx_str_set(&error, "用户名无效");
        rc = ngx_http_auth_cookie_serve_login_page(r, alcf, &next, &error, NGX_HTTP_OK);
        ngx_http_finalize_request(r, rc);
        return;
    }
    username = decoded;

    if (username.len > NGX_AUTH_COOKIE_MAX_USER_LEN
        || ngx_strlchr(username.data, username.data + username.len, '\0')
           != NULL)
    {
        ngx_explicit_memzero(body.data, body.len);
        if (alcf->rate.key_mode != NGX_AUTH_COOKIE_RATE_KEY_IP
            && ngx_http_auth_cookie_rate_body_check(r, alcf, NULL, &next)
               != NGX_OK)
        {
            return;
        }
        ngx_str_set(&error, "用户名无效");
        rc = ngx_http_auth_cookie_serve_login_page(r, alcf, &next, &error, NGX_HTTP_OK);
        ngx_http_finalize_request(r, rc);
        return;
    }

    for (i = 0; i < username.len; i++) {
        if (username.data[i] == ':' || username.data[i] == '\r'
            || username.data[i] == '\n')
        {
            ngx_explicit_memzero(body.data, body.len);
            if (alcf->rate.key_mode != NGX_AUTH_COOKIE_RATE_KEY_IP
                && ngx_http_auth_cookie_rate_body_check(r, alcf, NULL, &next)
                   != NGX_OK)
            {
                return;
            }
            ngx_str_set(&error, "用户名无效");
            rc = ngx_http_auth_cookie_serve_login_page(r, alcf, &next, &error, NGX_HTTP_OK);
            ngx_http_finalize_request(r, rc);
            return;
        }
    }

    if (alcf->rate.key_mode != NGX_AUTH_COOKIE_RATE_KEY_IP) {
        rc = ngx_http_auth_cookie_rate_check(r, &alcf->rate, &username);
        if (rc != NGX_AUTH_COOKIE_RATE_ALLOWED) {
            ngx_explicit_memzero(body.data, body.len);
            if (rc == NGX_AUTH_COOKIE_RATE_DENIED) {
                rc = ngx_http_auth_cookie_rate_limited(r, alcf, &next);
            } else if (rc == NGX_AUTH_COOKIE_RATE_BAD_IP) {
                rc = NGX_HTTP_BAD_REQUEST;
            } else {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            ngx_http_finalize_request(r, rc);
            return;
        }
    }

    if (ngx_http_auth_cookie_unescape(r->pool, &password, &decoded) != NGX_OK) {
        ngx_explicit_memzero(body.data, body.len);
        ngx_str_set(&error, "密码无效");
        rc = ngx_http_auth_cookie_serve_login_page(r, alcf, &next, &error, NGX_HTTP_OK);
        ngx_http_finalize_request(r, rc);
        return;
    }
    password = decoded;

    if (ngx_strlchr(password.data, password.data + password.len, '\0')
        != NULL)
    {
        ngx_explicit_memzero(password.data, password.len);
        ngx_explicit_memzero(body.data, body.len);
        ngx_str_set(&error, "密码无效");
        rc = ngx_http_auth_cookie_serve_login_page(r, alcf, &next, &error, NGX_HTTP_OK);
        ngx_http_finalize_request(r, rc);
        return;
    }

    /* 校验用户密码 */
    rc = ngx_http_auth_cookie_check_user(r, alcf->users, &username,
                                         &password);
    ngx_explicit_memzero(password.data, password.len);
    ngx_explicit_memzero(body.data, body.len);
    if (rc != NGX_OK) {
        if (rc != NGX_DECLINED) {
            ngx_http_finalize_request(r, rc);
            return;
        }
        ngx_str_set(&error, "用户名或密码错误");
        rc = ngx_http_auth_cookie_serve_login_page(r, alcf, &next, &error, NGX_HTTP_OK);
        ngx_http_finalize_request(r, rc);
        return;
    }

    /* 签发 cookie。无 Host 无法绑定会话,回登录页而不是 500。 */
    if (r->headers_in.server.len == 0) {
        ngx_str_set(&error, "缺少 Host,无法签发会话");
        rc = ngx_http_auth_cookie_serve_login_page(r, alcf, &next, &error, NGX_HTTP_OK);
        ngx_http_finalize_request(r, rc);
        return;
    }

    entry = ngx_http_auth_cookie_find_user(alcf->users, &username);
    if (entry == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ngx_http_auth_cookie_sign(r, &alcf->secret, alcf->user_file,
                                  entry->fingerprint, alcf->session_ttl,
                                  &username, &cookie)
        != NGX_OK)
    {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    rc = ngx_http_auth_cookie_set_cookie(r, alcf, &cookie, alcf->session_ttl);
    if (rc != NGX_OK) {
        ngx_http_finalize_request(r, rc);
        return;
    }

    if (next.len == 0) {
        ngx_str_set(&next, "/");
    }
    location = next;

    rc = ngx_http_auth_cookie_send_redirect(r, &location);
    ngx_http_finalize_request(r, rc);
}


/*
 * 构建未认证请求的重定向 URI:login_uri?next=原请求
 */
static ngx_int_t
ngx_http_auth_cookie_build_redirect_uri(ngx_http_request_t *r,
    ngx_http_auth_cookie_loc_conf_t *alcf, ngx_str_t *out)
{
    ngx_str_t   login_uri;
    size_t      escaped, len;
    u_char     *p;

    if (alcf->login_uri != NULL) {
        login_uri = *alcf->login_uri;
    } else {
        ngx_str_set(&login_uri, NGX_AUTH_COOKIE_DEFAULT_LOGIN_URI);
    }

    /* 使用未解码的 unparsed_uri,保留原始编码(%23/%3F 等)语义;
       编码形态会沿 next 链路一直保留到最终 Location。 */
    escaped = ngx_escape_uri(NULL, r->unparsed_uri.data, r->unparsed_uri.len,
                             NGX_ESCAPE_ARGS);
    len = login_uri.len + sizeof("?next=") - 1 + r->unparsed_uri.len
          + escaped * 2;

    out->data = ngx_pnalloc(r->pool, len);
    if (out->data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_cpymem(out->data, login_uri.data, login_uri.len);
    p = ngx_cpymem(p, "?next=", sizeof("?next=") - 1);
    p = (u_char *) ngx_escape_uri(p, r->unparsed_uri.data,
                                  r->unparsed_uri.len, NGX_ESCAPE_ARGS);

    out->len = p - out->data;
    return NGX_OK;
}


/*
 * content handler:登录/登出 URI 的实际处理。
 * 由 access 阶段设置 r->content_handler 接入,使同层 IP ACL、auth_basic、
 * auth_request 等联合访问控制先按 satisfy 规则执行,通过后才进入这里。
 */
static ngx_int_t
ngx_http_auth_cookie_endpoint_handler(ngx_http_request_t *r)
{
    ngx_http_auth_cookie_loc_conf_t  *alcf;
    ngx_str_t                         next, error;
    ngx_int_t                         rc;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_cookie_module);

    /* 登出 URI:仅 POST(access 阶段只放行 POST 进入这里) */
    if (alcf->logout_uri != NULL
        && ngx_http_auth_cookie_uri_equal(r, alcf->logout_uri) == NGX_OK)
    {
        if (r->method != NGX_HTTP_POST) {
            return NGX_HTTP_NOT_ALLOWED;
        }

        if (ngx_http_auth_cookie_check_csrf(r, alcf) != NGX_OK) {
            return NGX_HTTP_BAD_REQUEST;
        }

        if (ngx_http_auth_cookie_form_too_large(r)) {
            return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
        }

        rc = ngx_http_read_client_request_body(
                 r, ngx_http_auth_cookie_logout_body_handler);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
        return NGX_DONE;
    }

    /* 登录 URI */
    if (r->method == NGX_HTTP_POST) {
        if (alcf->rate.key_mode == NGX_AUTH_COOKIE_RATE_KEY_IP) {
            rc = ngx_http_auth_cookie_rate_check(r, &alcf->rate, NULL);
            if (rc == NGX_AUTH_COOKIE_RATE_BAD_IP) {
                return NGX_HTTP_BAD_REQUEST;
            }
            if (rc == NGX_AUTH_COOKIE_RATE_DENIED) {
                ngx_http_auth_cookie_get_next(r, &next);
                rc = ngx_http_discard_request_body(r);
                if (rc != NGX_OK) {
                    return rc;
                }
                return ngx_http_auth_cookie_rate_limited(r, alcf, &next);
            }
            if (rc != NGX_AUTH_COOKIE_RATE_ALLOWED) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        if (ngx_http_auth_cookie_check_csrf(r, alcf) != NGX_OK) {
            if (alcf->rate.key_mode != NGX_AUTH_COOKIE_RATE_KEY_IP) {
                rc = ngx_http_auth_cookie_rate_check(r, &alcf->rate, NULL);
                if (rc == NGX_AUTH_COOKIE_RATE_BAD_IP) {
                    return NGX_HTTP_BAD_REQUEST;
                }
                if (rc == NGX_AUTH_COOKIE_RATE_DENIED) {
                    ngx_http_auth_cookie_get_next(r, &next);
                    (void) ngx_http_discard_request_body(r);
                    return ngx_http_auth_cookie_rate_limited(r, alcf, &next);
                }
                if (rc != NGX_AUTH_COOKIE_RATE_ALLOWED) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
            }
            return NGX_HTTP_BAD_REQUEST;
        }

        if (ngx_http_auth_cookie_form_too_large(r)) {
            if (alcf->rate.key_mode != NGX_AUTH_COOKIE_RATE_KEY_IP) {
                rc = ngx_http_auth_cookie_rate_check(r, &alcf->rate, NULL);
                if (rc == NGX_AUTH_COOKIE_RATE_BAD_IP) {
                    return NGX_HTTP_BAD_REQUEST;
                }
                if (rc == NGX_AUTH_COOKIE_RATE_DENIED) {
                    ngx_http_auth_cookie_get_next(r, &next);
                    (void) ngx_http_discard_request_body(r);
                    return ngx_http_auth_cookie_rate_limited(r, alcf, &next);
                }
                if (rc != NGX_AUTH_COOKIE_RATE_ALLOWED) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
            }
            return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
        }

        rc = ngx_http_read_client_request_body(
                 r, ngx_http_auth_cookie_login_body_handler);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
        return NGX_DONE;
    }

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    /* GET/HEAD 登录页:先按请求边界丢弃可能存在的 body,再渲染页面。 */
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_http_auth_cookie_get_next(r, &next);
    ngx_str_null(&error);
    return ngx_http_auth_cookie_serve_login_page(r, alcf, &next, &error, NGX_HTTP_OK);
}


/*
 * access handler:主入口
 */
static ngx_int_t
ngx_http_auth_cookie_handler(ngx_http_request_t *r)
{
    ngx_http_auth_cookie_loc_conf_t  *alcf;
    ngx_http_auth_cookie_ctx_t       *ctx;
    ngx_str_t                         user, cookie_value;
    ngx_str_t                         redirect_uri;
    ngx_int_t                         rc;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_cookie_module);

    if (!alcf->enabled) {
        return NGX_DECLINED;
    }

    /* 登出 URI 优先:POST 清除 cookie(无论是否已登录)。
     * 只登记 content handler 并放行,联合访问控制由后续 access handler 执行。 */
    if (r->method == NGX_HTTP_POST && alcf->logout_uri != NULL
        && ngx_http_auth_cookie_uri_equal(r, alcf->logout_uri) == NGX_OK)
    {
        r->content_handler = ngx_http_auth_cookie_endpoint_handler;
        return NGX_DECLINED;
    }

    /* 登录 URI:渲染或处理登录,同样交给 content 阶段执行。 */
    if (alcf->login_uri != NULL
        && ngx_http_auth_cookie_uri_equal(r, alcf->login_uri) == NGX_OK)
    {
        r->content_handler = ngx_http_auth_cookie_endpoint_handler;
        return NGX_DECLINED;
    }

    /* 同一请求内部重定向时复用已完成的验签结果。 */
    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_cookie_module);
    if (ctx != NULL && ctx->authed) {
        return NGX_OK;
    }

    /* 校验 cookie:先按 payload 解用户,再绑定该用户当前哈希指纹。 */
    if (ngx_http_auth_cookie_get_cookie(r, &alcf->cookie_name,
                                        &cookie_value)
        == NGX_OK)
    {
        ngx_http_auth_cookie_user_t  *entry;

        if (ngx_http_auth_cookie_peek_user(r, &cookie_value, &user) == NGX_OK
            && (entry = ngx_http_auth_cookie_find_user(alcf->users, &user))
               != NULL
            && ngx_http_auth_cookie_verify(r, &alcf->secret, alcf->user_file,
                                           entry->fingerprint, &cookie_value,
                                           &user)
               == NGX_OK)
        {
            ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_cookie_ctx_t));
            if (ctx == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            ctx->user = user;
            ctx->authed = 1;
            ngx_http_set_ctx(r, ctx, ngx_http_auth_cookie_module);

            return NGX_OK;
        }
    }

    /* 未认证:302 到登录页?next=原请求 */
    rc = ngx_http_auth_cookie_build_redirect_uri(r, alcf, &redirect_uri);
    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_http_auth_cookie_send_redirect(r, &redirect_uri);
}
