/*
 * ngx_http_auth_cookie_module — htpasswd 用户表实现
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_crypt.h>
#include <openssl/evp.h>

#include "ngx_http_auth_cookie_htpasswd.h"
#include "ngx_http_auth_cookie_util.h"


static ngx_int_t
ngx_http_auth_cookie_hash_supported(ngx_str_t *hash)
{
    if (hash->len > sizeof("$apr1$") - 1
        && ngx_strncmp(hash->data, "$apr1$", sizeof("$apr1$") - 1) == 0)
    {
        return NGX_OK;
    }

    if (hash->len > sizeof("$2x$") - 1 && hash->data[0] == '$'
        && hash->data[1] == '2'
        && (hash->data[2] == 'a' || hash->data[2] == 'b'
            || hash->data[2] == 'y')
        && hash->data[3] == '$')
    {
        return NGX_OK;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_auth_cookie_user_fingerprint(ngx_str_t *hash, u_char *out)
{
    unsigned int  out_len = 0;

    if (EVP_Digest(hash->data, hash->len, out, &out_len, EVP_sha256(), NULL)
        != 1
        || out_len != NGX_AUTH_COOKIE_HMAC_SHA256_LEN)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_cookie_check_password(ngx_http_request_t *r,
    ngx_str_t *passwd, ngx_str_t *hash)
{
    u_char     *encrypted;
    u_char     *key, *salt;
    ngx_int_t   rc;

    if (hash->len == 0 || passwd->len == 0) {
        return NGX_DECLINED;
    }

    if (ngx_http_auth_cookie_hash_supported(hash) != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                      "auth_cookie: unsupported password hash in htpasswd");
        return NGX_DECLINED;
    }

    key = ngx_pnalloc(r->pool, passwd->len + 1);
    if (key == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(key, passwd->data, passwd->len);
    key[passwd->len] = '\0';

    salt = ngx_pnalloc(r->pool, hash->len + 1);
    if (salt == NULL) {
        ngx_explicit_memzero(key, passwd->len + 1);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(salt, hash->data, hash->len);
    salt[hash->len] = '\0';

    rc = ngx_crypt(r->pool, key, salt, &encrypted);
    ngx_explicit_memzero(key, passwd->len + 1);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_cookie: password hash verification failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_strlen(encrypted) != hash->len
        || ngx_http_auth_cookie_constant_eq(encrypted, salt, hash->len)
           != NGX_OK)
    {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


ngx_http_auth_cookie_user_t *
ngx_http_auth_cookie_find_user(ngx_array_t *users, ngx_str_t *name)
{
    ngx_http_auth_cookie_user_t  *user;
    ngx_uint_t                    i;

    if (users == NULL || name->len == 0) {
        return NULL;
    }

    user = users->elts;
    for (i = 0; i < users->nelts; i++) {
        if (user[i].name.len == name->len
            && ngx_strncmp(user[i].name.data, name->data, name->len) == 0)
        {
            return &user[i];
        }
    }

    return NULL;
}


ngx_int_t
ngx_http_auth_cookie_check_user(ngx_http_request_t *r,
    ngx_array_t *users, ngx_str_t *user, ngx_str_t *passwd)
{
    ngx_http_auth_cookie_user_t  *entry;

    entry = ngx_http_auth_cookie_find_user(users, user);
    if (entry == NULL) {
        return NGX_DECLINED;
    }

    return ngx_http_auth_cookie_check_password(r, passwd, &entry->hash);
}


ngx_int_t
ngx_http_auth_cookie_load_users(ngx_pool_t *pool, ngx_log_t *log,
    ngx_str_t *user_file, ngx_array_t **users)
{
    ngx_fd_t                      fd;
    ngx_file_t                    file;
    ngx_file_info_t               fi;
    ssize_t                       n;
    size_t                        size, i, line_start, name_len, hash_off;
    u_char                       *buf, *p, *line_end;
    ngx_array_t                  *table;
    ngx_http_auth_cookie_user_t  *entry;
    ngx_str_t                     name, hash;

    fd = ngx_open_file(user_file->data,
                       NGX_FILE_RDONLY|NGX_FILE_NONBLOCK|O_NOFOLLOW,
                       NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "auth_cookie: open user file \"%s\" failed",
                      user_file->data);
        return NGX_ERROR;
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR || !ngx_is_file(&fi)
        || ngx_file_size(&fi) > NGX_AUTH_COOKIE_USER_FILE_MAX)
    {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "auth_cookie: user file \"%s\" must be a regular file up to 1MB",
                      user_file->data);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.fd = fd;
    file.name = *user_file;
    file.log = log;

    size = (size_t) ngx_file_size(&fi);
    buf = ngx_pnalloc(pool, size + 1);
    if (buf == NULL) {
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    n = ngx_read_file(&file, buf, size, 0);
    ngx_close_file(fd);
    if (n != (ssize_t) size) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "auth_cookie: read user file \"%s\" failed",
                      user_file->data);
        return NGX_ERROR;
    }
    buf[size] = '\0';

    table = ngx_array_create(pool, 8, sizeof(ngx_http_auth_cookie_user_t));
    if (table == NULL) {
        return NGX_ERROR;
    }

    i = 0;
    while (i < size) {
        line_start = i;
        while (i < size && buf[i] != LF) {
            i++;
        }
        line_end = buf + i;
        if (i < size && buf[i] == LF) {
            i++;
        }
        if (line_end > buf + line_start && line_end[-1] == CR) {
            line_end--;
        }

        p = buf + line_start;
        if (p == line_end || *p == '#') {
            continue;
        }

        while (p < line_end && *p != ':') {
            p++;
        }
        if (p == line_end || p == buf + line_start) {
            ngx_log_error(NGX_LOG_EMERG, log, 0,
                          "auth_cookie: invalid user file line in \"%s\"",
                          user_file->data);
            return NGX_ERROR;
        }

        name_len = p - (buf + line_start);
        if (name_len > NGX_AUTH_COOKIE_MAX_USER_LEN
            || ngx_strlchr(buf + line_start, p, '\0') != NULL)
        {
            ngx_log_error(NGX_LOG_EMERG, log, 0,
                          "auth_cookie: invalid username in \"%s\"",
                          user_file->data);
            return NGX_ERROR;
        }

        hash_off = (p + 1) - buf;
        p++;
        while (p < line_end && *p != ':') {
            p++;
        }

        name.data = buf + line_start;
        name.len = name_len;
        hash.data = buf + hash_off;
        hash.len = p - hash.data;

        if (ngx_http_auth_cookie_hash_supported(&hash) != NGX_OK) {
            ngx_log_error(NGX_LOG_EMERG, log, 0,
                          "auth_cookie: unsupported password hash in \"%s\"",
                          user_file->data);
            return NGX_ERROR;
        }

        if (ngx_http_auth_cookie_find_user(table, &name) != NULL) {
            continue;
        }

        entry = ngx_array_push(table);
        if (entry == NULL) {
            return NGX_ERROR;
        }

        entry->name = name;
        entry->hash = hash;
        if (ngx_http_auth_cookie_user_fingerprint(&hash, entry->fingerprint)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_EMERG, log, 0,
                          "auth_cookie: hash fingerprint failed in \"%s\"",
                          user_file->data);
            return NGX_ERROR;
        }
    }

    *users = table;
    return NGX_OK;
}
