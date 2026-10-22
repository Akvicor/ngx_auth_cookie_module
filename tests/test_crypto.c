/*
 * 正式实现的单元测试:编译仓库根目录下真实的 crypto.c 与 util.c,
 * 覆盖 HMAC 向量、签发/解析/验签、篡改/过期/绑定关系、
 * base64url/hex、sanitize_next 与 load_secret。
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_auth_cookie_util.h"
#include "ngx_http_auth_cookie_crypto.h"


/* ---- 桩函数实现 ---- */

u_char *
ngx_sprintf(u_char *buf, const char *fmt, ...)
{
    va_list  ap;

    va_start(ap, fmt);
    while (*fmt) {
        if (*fmt == '%' && fmt[1] == 'T') {
            time_t  t = va_arg(ap, time_t);
            buf += sprintf((char *) buf, "%lld", (long long) t);
            fmt += 2;
        } else {
            *buf++ = (u_char) *fmt++;
        }
    }
    va_end(ap);
    return buf;
}


ngx_int_t
ngx_atoi(u_char *line, size_t n)
{
    ngx_int_t  value, cutoff, cutlim;

    if (n == 0) {
        return NGX_ERROR;
    }

    cutoff = NGX_ERROR / 10;   /* 与 nginx 一致,仅非负 */
    (void) cutoff;
    cutlim = 0;
    (void) cutlim;

    value = 0;
    for (; n--; line++) {
        if (*line < '0' || *line > '9') {
            return NGX_ERROR;
        }
        value = value * 10 + (*line - '0');
    }

    return value;
}


void
ngx_log_error(int level, ngx_log_t *log, int err, const char *fmt, ...)
{
    va_list  ap;

    (void) level;
    (void) log;

    va_start(ap, fmt);
    fprintf(stderr, "stub log (err=%d): ", err);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}


/* ---- 测试工具 ---- */

static int        failures = 0;
static ngx_pool_t test_pool;
static ngx_log_t  test_log;

#define CHECK(name, cond)                                                     \
    do {                                                                      \
        if (cond) {                                                           \
            printf("PASS  %s\n", name);                                       \
        } else {                                                              \
            printf("FAIL  %s\n", name);                                       \
            failures++;                                                       \
        }                                                                     \
    } while (0)


static ngx_http_request_t *
make_request(const char *server, const char *host)
{
    static ngx_table_elt_t  host_elt;
    ngx_http_request_t     *r;

    r = calloc(1, sizeof(*r));
    r->pool = &test_pool;
    r->headers_in.server.data = (u_char *) server;
    r->headers_in.server.len = strlen(server);

    if (host != NULL) {
        host_elt.value.data = (u_char *) host;
        host_elt.value.len = strlen(host);
        r->headers_in.host = &host_elt;
    } else {
        r->headers_in.host = NULL;
    }

    return r;
}


static ngx_str_t
str(const char *s)
{
    ngx_str_t  v;

    v.data = (u_char *) s;
    v.len = strlen(s);
    return v;
}


/* ---- HMAC 向量 ---- */

static void
check_hmac(const u_char *key, size_t key_len, const u_char *data,
    size_t data_len, const char *expected, const char *name)
{
    u_char  digest[NGX_AUTH_COOKIE_HMAC_SHA256_LEN];
    char    actual[NGX_AUTH_COOKIE_HMAC_SHA256_LEN * 2 + 1];
    size_t  i;

    if (ngx_http_auth_cookie_hmac_sha256(key, key_len, data, data_len, digest)
        != NGX_OK)
    {
        CHECK(name, 0);
        return;
    }

    for (i = 0; i < sizeof(digest); i++) {
        (void) snprintf(actual + i * 2, 3, "%02x", digest[i]);
    }
    actual[sizeof(digest) * 2] = '\0';

    CHECK(name, strcmp(actual, expected) == 0);
}


/* ---- sanitize_next 用例 ---- */

static void
check_sanitize(const char *name, const char *input, const char *host,
    const char *expected)
{
    ngx_http_request_t  *r;
    ngx_str_t            next;

    r = make_request(host, host);
    next = str(input);
    ngx_http_auth_cookie_sanitize_next(r, &next);

    if (expected == NULL) {
        CHECK(name, next.len == 0);
        return;
    }

    CHECK(name, next.len == strlen(expected)
                && memcmp(next.data, expected, next.len) == 0);
}


/* ---- 主流程 ---- */

int
main(void)
{
    u_char               key1[20], key3[131];
    ngx_http_request_t  *r;
    ngx_str_t            secret, audience, user, cookie;
    ngx_http_auth_cookie_session_t session;
    u_char               fp[32], fp2[32];
    char                 path[128];
    const char          *tmp;
    int                  fd;

    /* HMAC-SHA256 RFC 4231 向量 */
    memset(key1, 0x0b, sizeof(key1));
    check_hmac(key1, sizeof(key1), (u_char *) "Hi There", 8,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        "hmac_vector_1");
    check_hmac((u_char *) "Jefe", 4,
        (u_char *) "what do ya want for nothing?", 28,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        "hmac_vector_2");
    memset(key3, 0xaa, sizeof(key3));
    check_hmac(key3, sizeof(key3),
        (u_char *) "Test Using Larger Than Block-Size Key - Hash Key First",
        sizeof("Test Using Larger Than Block-Size Key - Hash Key First") - 1,
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        "hmac_vector_3");

    /* 签发/验签 */
    memset(fp, 0x11, sizeof(fp));
    memset(fp2, 0x22, sizeof(fp2));
    secret = str("0123456789abcdef0123456789abcdef");
    audience = str("/etc/nginx/htpasswd");

    r = make_request("app.test", "app.test");
    user = str("user1");

    CHECK("sign_ok",
          ngx_http_auth_cookie_sign(r, &secret, &audience, fp, 3600, &user,
                                    &cookie)
          == NGX_OK);
    CHECK("verify_ok",
          ngx_http_auth_cookie_parse(r, &cookie, &session) == NGX_OK
          && ngx_http_auth_cookie_verify(r, &secret, &audience, fp, &session)
          == NGX_OK
          && session.user.len == user.len
          && memcmp(session.user.data, user.data, user.len) == 0);

    /* 篡改签名 */
    cookie.data[cookie.len - 1] =
        (cookie.data[cookie.len - 1] == '0') ? '1' : '0';
    CHECK("tampered_rejected",
          ngx_http_auth_cookie_parse(r, &cookie, &session) == NGX_OK
          && ngx_http_auth_cookie_verify(r, &secret, &audience, fp, &session)
          == NGX_DECLINED);

    /* 重新签发干净的 cookie 用于绑定测试 */
    CHECK("sign_ok_again",
          ngx_http_auth_cookie_sign(r, &secret, &audience, fp, 3600, &user,
                                    &cookie)
          == NGX_OK);
    CHECK("parse_session", ngx_http_auth_cookie_parse(r, &cookie, &session)
                           == NGX_OK);

    {
        const char *invalid[] = { "", "bad", "bad.00",
            "*.0000000000000000000000000000000000000000000000000000000000000000" };
        size_t i;
        ngx_str_t malformed;

        for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
            malformed = str(invalid[i]);
            CHECK("malformed_cookie_rejected",
                  ngx_http_auth_cookie_parse(r, &malformed, &session)
                  == NGX_DECLINED);
        }
        /* 失败解析后的结果不能用于验签，恢复已成功解析的会话。 */
        CHECK("parse_after_malformed",
              ngx_http_auth_cookie_parse(r, &cookie, &session) == NGX_OK);
    }

    /* Host 绑定 */
    r = make_request("other.test", "other.test");
    CHECK("cross_host_rejected",
          ngx_http_auth_cookie_verify(r, &secret, &audience, fp, &session)
          == NGX_DECLINED);

    /* audience(用户文件)绑定 */
    r = make_request("app.test", "app.test");
    {
        ngx_str_t  other_audience = str("/other");

        CHECK("cross_audience_rejected",
              ngx_http_auth_cookie_verify(r, &secret, &other_audience, fp,
                                          &session)
              == NGX_DECLINED);
    }

    /* 密码指纹绑定 */
    CHECK("cross_fingerprint_rejected",
          ngx_http_auth_cookie_verify(r, &secret, &audience, fp2, &session)
          == NGX_DECLINED);

    /* 过期 */
    CHECK("sign_zero_ttl_rejected",
          ngx_http_auth_cookie_sign(r, &secret, &audience, fp, 0, &user,
                                    &cookie)
          == NGX_ERROR);
    CHECK("sign_short_ttl_ok",
          ngx_http_auth_cookie_sign(r, &secret, &audience, fp, 1, &user,
                                    &cookie)
          == NGX_OK);
    sleep(2);
    CHECK("expired_rejected",
          ngx_http_auth_cookie_parse(r, &cookie, &session) == NGX_OK
          && ngx_http_auth_cookie_verify(r, &secret, &audience, fp, &session)
          == NGX_DECLINED);

    /* base64url / hex 往返 */
    {
        ngx_str_t  enc, dec;

        CHECK("b64url_roundtrip",
              ngx_http_auth_cookie_b64url_encode(&test_pool,
                  (u_char *) "a/b+c=d", 7, &enc) == NGX_OK
              && ngx_http_auth_cookie_b64url_decode(&test_pool, enc.data,
                                                    enc.len, &dec) == NGX_OK
              && dec.len == 7 && memcmp(dec.data, "a/b+c=d", 7) == 0);
        CHECK("b64url_invalid_rejected",
              ngx_http_auth_cookie_b64url_decode(&test_pool,
                  (u_char *) "a*=", 3, &dec) == NGX_ERROR);
    }

    /* sanitize_next */
    check_sanitize("next_relative_ok", "/private/page", "app.test",
                   "/private/page");
    check_sanitize("next_encoded_preserved", "/report%23draft", "app.test",
                   "/report%23draft");
    check_sanitize("next_encoded_query_preserved", "/a%3Fb?x=1", "app.test",
                   "/a%3Fb?x=1");
    check_sanitize("next_double_slash_rejected", "//evil.test/", "app.test",
                   NULL);
    check_sanitize("next_encoded_double_slash_rejected", "/%2F%2Fevil.test/",
                   "app.test", NULL);
    check_sanitize("next_plus_preserved", "/search?q=a+b", "app.test",
                   "/search?q=a+b");
    check_sanitize("next_space_encoded_preserved", "/a%20b", "app.test",
                   "/a%20b");
    check_sanitize("next_raw_space_rejected", "/a b", "app.test", NULL);
    check_sanitize("next_raw_backslash_rejected", "/\\evil", "app.test", NULL);
    check_sanitize("next_encoded_authority_slash_rejected",
                   "https://app.test%2Fa//evil.test/", "app.test", NULL);
    check_sanitize("next_encoded_authority_dot_rejected",
                   "https://app%2Etest/x", "app.test", NULL);
    check_sanitize("next_raw_hash_rejected", "/a#b", "app.test", NULL);
    check_sanitize("next_control_rejected", "/a%0db", "app.test", NULL);
    check_sanitize("next_backslash_rejected", "/%5Cevil", "app.test", NULL);
    check_sanitize("next_absolute_same_host", "https://app.test/a%23b",
                   "app.test", "/a%23b");
    check_sanitize("next_absolute_no_path", "https://app.test", "app.test",
                   "/");
    check_sanitize("next_absolute_double_slash_rejected",
                   "https://app.test//evil.test/", "app.test", NULL);
    check_sanitize("next_absolute_cross_host", "https://evil.test/a",
                   "app.test", NULL);
    check_sanitize("next_absolute_host_with_port", "http://app.test:8080/a",
                   "app.test:8080", "/a");
    check_sanitize("next_encoded_scheme_rejected", "https%3A//app.test/a",
                   "app.test", NULL);

    /* load_secret:不存在则生成 0600,已有则读取 */
    /* 跟随运行器的独占目录，生成与重新读取后立即清理测试密钥文件。 */
    tmp = getenv("TMPDIR");
    if (tmp == NULL || tmp[0] == '\0') {
        tmp = P_tmpdir;
    }
    snprintf(path, sizeof(path), "%s/ac-secret.XXXXXX", tmp);
    fd = mkstemp(path);
    if (fd >= 0) {
        close(fd);
        unlink(path);   /* 删除后走“不存在则生成”路径 */
    }

    {
        ngx_str_t  secret_file = str(path);
        ngx_str_t  loaded;
        struct stat st;

        ngx_str_null(&loaded);
        CHECK("secret_generated",
              ngx_http_auth_cookie_load_secret(&test_pool, &test_log,
                                               &secret_file, &loaded)
              == NGX_OK && loaded.len == 64);
        CHECK("secret_file_0600",
              stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);

        ngx_str_null(&loaded);
        CHECK("secret_reloaded",
              ngx_http_auth_cookie_load_secret(&test_pool, &test_log,
                                               &secret_file, &loaded)
              == NGX_OK && loaded.len == 64);
    }

    /* 过短的 secret 被拒绝 */
    unlink(path);
    snprintf(path, sizeof(path), "%s/ac-secret-short.XXXXXX", tmp);
    fd = mkstemp(path);
    if (fd >= 0) {
        write(fd, "tooshort", 8);
        close(fd);
        chmod(path, 0600);

        {
            ngx_str_t  secret_file = str(path);
            ngx_str_t  loaded;

            ngx_str_null(&loaded);
            CHECK("short_secret_rejected",
                  ngx_http_auth_cookie_load_secret(&test_pool, &test_log,
                                                   &secret_file, &loaded)
                  == NGX_ERROR);
        }
        unlink(path);
    }

    if (failures) {
        printf("---- %d test(s) failed ----\n", failures);
        return 1;
    }

    puts("all crypto/util unit tests passed");
    return 0;
}
