#!/bin/sh
# Basic 兼容入口、Cookie 共存、内部重定向和联合访问控制回归。
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 /path/to/nginx" >&2
    exit 2
fi

NGX_BIN=$(realpath "$1")
PORT=${PORT:-18140}
TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/auth-cookie-basic.XXXXXX")
unset NGINX
PASS=0
FAIL=0

cleanup() {
    if [ -f "$TEST_DIR/nginx.pid" ]; then
        "$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf" -s quit \
            >/dev/null 2>&1 || true
        sleep 0.3
        if [ -f "$TEST_DIR/nginx.pid" ]; then
            kill "$(cat "$TEST_DIR/nginx.pid")" >/dev/null 2>&1 || true
        fi
    fi
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT HUP INT TERM

ok() { PASS=$((PASS + 1)); echo "PASS  $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL  $1 (got=$2 expect=$3)"; }
eq() { [ "$2" = "$3" ] && ok "$1" || bad "$1" "$2" "$3"; }

# 每次请求都检查认证挑战，覆盖成功、失败及网页登录响应。
request() {
    label=$1
    expected=$2
    path=$3
    shift 3
    code=$(curl -sS --max-time 5 -D "$TEST_DIR/headers" -o "$TEST_DIR/body" \
        -w '%{http_code}' -H 'Host: localhost' "$@" "$BASE$path")
    eq "$label" "$code" "$expected"
    if grep -qi '^WWW-Authenticate:' "$TEST_DIR/headers"; then
        bad "${label}_no_challenge" present absent
    else
        ok "${label}_no_challenge"
    fi
}

mkdir -p "$TEST_DIR/www" "$TEST_DIR/logs"
chmod 755 "$TEST_DIR" "$TEST_DIR/www" "$TEST_DIR/logs"
printf '%s\n' protected > "$TEST_DIR/www/index.html"
for loc in bcrypt colon other deny any allow native check public csrf-off invalid-user long-valid long-invalid \
    rate-basic rate-form rate-error rate-malformed rate-ip rate-username \
    rate-trusted rate-untrusted rate-empty rate-csrf rate-bad-user rate-concurrent \
    basic-off rate-norefund rate-norefund-form; do
    mkdir -p "$TEST_DIR/www/$loc"
    printf '%s\n' protected > "$TEST_DIR/www/$loc/index.html"
done
printf 'admin:%s\n' "$(openssl passwd -apr1 -salt testsalt admin123)" \
    > "$TEST_DIR/htpasswd"
printf 'admin:%s\n' "$(openssl passwd -apr1 -salt testsalt changed123)" \
    > "$TEST_DIR/other"
printf 'admin:%s\n' "$(openssl passwd -apr1 -salt testsalt 'admin:123')" \
    > "$TEST_DIR/colon"
# 固定 bcrypt(cost 4) 向量对应 admin123，测试不依赖 htpasswd 工具。
printf '%s\n' 'admin:$2a$04$J2rximSmksTVCthpkunvb.VC2tgjXZQzP.7JWbkII47NAjde2PDi2' \
    > "$TEST_DIR/bcrypt"
printf 'admin\rname:%s\n' "$(openssl passwd -apr1 -salt testsalt admin123)" \
    > "$TEST_DIR/invalid-user"
LONG_PASSWORD=$(awk 'BEGIN { for (i = 0; i < 4096; i++) printf "a" }')
# 固定 APR1 向量对应 4096/4097 个 a；openssl passwd 会把输入截到 256 字节。
printf '%s\n' 'admin:$apr1$testsalt$u8UPZxtTjdzWkJS4yYOUW1' > "$TEST_DIR/long-valid"
printf '%s\n' 'admin:$apr1$testsalt$gHbtUTo.bbNi7rIGpWPCu.' > "$TEST_DIR/long-invalid"

cat > "$TEST_DIR/nginx.conf" <<EOF
worker_processes 2;
error_log $TEST_DIR/error.log notice;
pid $TEST_DIR/nginx.pid;
events { worker_connections 128; }
http {
    log_format audit '\$request_uri user=\$auth_cookie_user';
    access_log $TEST_DIR/access.log audit;
    client_body_temp_path $TEST_DIR/body_temp;
    proxy_temp_path $TEST_DIR/proxy_temp;
    fastcgi_temp_path $TEST_DIR/fastcgi_temp;
    uwsgi_temp_path $TEST_DIR/uwsgi_temp;
    scgi_temp_path $TEST_DIR/scgi_temp;
    server {
        listen 127.0.0.1:$PORT;
        server_name localhost;
        root $TEST_DIR/www;
        index index.html;
        auth_cookie_user_file $TEST_DIR/htpasswd;
        auth_cookie_secret $TEST_DIR/secret;
        auth_cookie_secure off;
        auth_cookie_logout_uri /_logout;
        auth_cookie_login_rate off;
        location / { }
        location /bcrypt/ { auth_cookie_user_file $TEST_DIR/bcrypt; }
        location /colon/ { auth_cookie_user_file $TEST_DIR/colon; }
        location /other/ { auth_cookie_user_file $TEST_DIR/other; }
        location /deny/ { satisfy all; deny all; }
        location /any/ { satisfy any; deny all; }
        location /allow/ { satisfy any; allow all; }
        location /csrf-off/ { auth_cookie_csrf off; }
        location /invalid-user/ {
            auth_cookie_user_file $TEST_DIR/invalid-user;
            auth_cookie_login_uri /invalid-user/_login;
        }
        location /long-valid/ {
            auth_cookie_user_file $TEST_DIR/long-valid;
            auth_cookie_login_uri /long-valid/_login;
        }
        location /long-invalid/ {
            auth_cookie_user_file $TEST_DIR/long-invalid;
            auth_cookie_login_uri /long-invalid/_login;
        }
        location /native/ {
            auth_basic "Legacy";
            auth_basic_user_file $TEST_DIR/htpasswd;
        }
        location /check/ { auth_request /_denied; }
        location = /_denied { internal; auth_cookie_user_file off; return 403; }
        location /public/ { auth_cookie_user_file off; }
        location /to-other/ { error_page 404 = /other/index.html; }
        location /to-public/ { error_page 404 = /public/index.html; }
        location /proxy/ {
            proxy_set_header X-Auth-User \$auth_cookie_user;
            proxy_pass http://127.0.0.1:$((PORT + 1));
        }
        # 长周期使连续请求稳定耗尽令牌，分别覆盖两种入口与三种统计键。
        location /rate-basic/ {
            auth_cookie_login_uri /rate-basic/_login;
            auth_cookie_login_rate 10 60s 1 60s;
        }
        location /rate-form/ {
            auth_cookie_login_uri /rate-form/_login;
            auth_cookie_login_rate 10 60s 1 60s;
        }
        location /rate-error/ {
            auth_cookie_login_uri /rate-error/_login;
            auth_cookie_login_rate 10 60s 1 60s;
        }
        location /rate-malformed/ {
            auth_cookie_login_uri /rate-malformed/_login;
            auth_cookie_login_rate 1 60s 1 60s;
        }
        location /rate-ip/ {
            auth_cookie_login_uri /rate-ip/_login;
            auth_cookie_login_rate 1 60s 10 60s;
            auth_cookie_login_rate_key ip;
        }
        location /rate-username/ {
            auth_cookie_login_uri /rate-username/_login;
            auth_cookie_login_rate 10 60s 1 60s;
            auth_cookie_login_rate_key username;
        }
        location /rate-trusted/ {
            auth_cookie_login_uri /rate-trusted/_login;
            auth_cookie_login_rate 10 60s 1 60s;
            auth_cookie_login_rate_trusted_proxy 127.0.0.1;
            auth_cookie_login_rate_ip_header X-Client-IP;
        }
        location /rate-untrusted/ {
            auth_cookie_login_uri /rate-untrusted/_login;
            auth_cookie_login_rate 10 60s 1 60s;
            auth_cookie_login_rate_trusted_proxy 203.0.113.0/24;
            auth_cookie_login_rate_ip_header X-Client-IP;
        }
        location /rate-empty/ {
            auth_cookie_login_uri /rate-empty/_login;
            auth_cookie_login_rate 10 60s 1 60s;
        }
        location /rate-csrf/ {
            auth_cookie_login_uri /rate-csrf/_login;
            auth_cookie_login_rate 10 60s 1 60s;
        }
        location /rate-bad-user/ {
            auth_cookie_login_uri /rate-bad-user/_login;
            auth_cookie_login_rate 1 60s 10 60s;
            auth_cookie_login_rate_key username;
        }
        location /rate-concurrent/ {
            auth_cookie_login_uri /rate-concurrent/_login;
            auth_cookie_login_rate 1 60s 1 60s;
        }
        location /basic-off/ {
            auth_cookie_basic off;
            auth_cookie_login_uri /basic-off/_login;
            auth_cookie_login_rate 1 60s 1 60s;
        }
        location /rate-norefund/ {
            auth_cookie_login_uri /rate-norefund/_login;
            auth_cookie_login_rate 10 60s 1 60s;
            auth_cookie_login_rate_refund off;
        }
        location /rate-norefund-form/ {
            auth_cookie_login_uri /rate-norefund-form/_login;
            auth_cookie_login_rate 10 60s 1 60s;
            auth_cookie_login_rate_refund off;
        }
    }
    server {
        listen 127.0.0.1:$((PORT + 1));
        location / {
            return 200 "\$request_method|\$http_authorization|\$http_x_auth_user|\$http_content_length";
        }
    }
}
EOF

"$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf" -t
"$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf"
BASE="http://127.0.0.1:$PORT"
AUTH=$(printf 'admin:admin123' | openssl base64 -A)
JAR="$TEST_DIR/cookies"

request browser_redirect 302 /index.html
grep -qi '^Location: .*\/_login?next=' "$TEST_DIR/headers" \
    && ok login_location || bad login_location missing present
request login_page 200 /_login
request basic_apr1 200 /index.html -u admin:admin123
eq protected_content "$(cat "$TEST_DIR/body")" protected
if grep -qi '^Set-Cookie:' "$TEST_DIR/headers"; then
    bad basic_no_session present absent
else
    ok basic_no_session
fi
request basic_index_redirect 200 / -u admin:admin123
request basic_bcrypt 200 /bcrypt/index.html -u admin:admin123
request basic_colon_password 200 /colon/index.html -u 'admin:admin:123'
request basic_head 200 /index.html -I -u admin:admin123
request basic_case_insensitive 200 /index.html -H "Authorization: bAsIc   $AUTH"
request basic_proxy_get 200 /proxy/ -u admin:admin123
eq proxy_headers "$(cat "$TEST_DIR/body")" "GET|Basic $AUTH|admin|"
request basic_proxy_post 200 /proxy/ -u admin:admin123 -d 'payload'
eq proxy_method_length "$(cat "$TEST_DIR/body")" "POST|Basic $AUTH|admin|7"
request basic_large_upload 200 /proxy/ -u admin:admin123 \
    -d "$LONG_PASSWORD$LONG_PASSWORD$LONG_PASSWORD"
eq proxy_large_upload_length "$(cat "$TEST_DIR/body")" "POST|Basic $AUTH|admin|12288"
request basic_chunked_upload 200 /proxy/ -u admin:admin123 \
    -H 'Transfer-Encoding: chunked' -d payload
eq proxy_chunked_upload_length "$(cat "$TEST_DIR/body")" "POST|Basic $AUTH|admin|7"
request basic_wrong_password 401 /index.html -u admin:wrong
request basic_unknown_user 401 /index.html -u missing:admin123
request basic_empty_password 401 /index.html -u admin:
request basic_empty_user 401 /index.html -u :admin123
request basic_empty_payload 401 /index.html -H 'Authorization: Basic'
request basic_bad_base64 401 /index.html -H 'Authorization: Basic !!!'
request basic_missing_colon 401 /index.html \
    -H "Authorization: Basic $(printf 'admin' | openssl base64 -A)"
request basic_nul_password 401 /index.html \
    -H "Authorization: Basic $(printf 'admin:admin123\000suffix' | openssl base64 -A)"
request basic_nul_user 401 /index.html \
    -H "Authorization: Basic $(printf 'admin\000:admin123' | openssl base64 -A)"
request basic_cr_username 401 /invalid-user/index.html \
    -H "Authorization: Basic $(printf 'admin\rname:admin123' | openssl base64 -A)"
request form_cr_username 200 /invalid-user/_login \
    -d 'username=admin%0Dname&password=admin123'
grep -q '用户名无效' "$TEST_DIR/body" \
    && ok form_cr_username_rejected || bad form_cr_username_rejected missing present
request basic_cross_origin 400 /index.html -u admin:admin123 -H 'Origin: https://other.test'
request basic_origin_null 400 /index.html -u admin:admin123 -H 'Origin: null'
request basic_cross_site 400 /index.html -u admin:admin123 -H 'Sec-Fetch-Site: cross-site'
request basic_same_origin 200 /index.html -u admin:admin123 -H 'Origin: https://localhost'
request basic_csrf_off 200 /csrf-off/index.html -u admin:admin123 -H 'Origin: null'
request basic_password_max 200 /long-valid/index.html -u "admin:$LONG_PASSWORD"
request form_password_max 302 /long-valid/_login \
    --data-urlencode username=admin --data-urlencode "password=$LONG_PASSWORD"
request basic_password_over_max 401 /long-invalid/index.html -u "admin:${LONG_PASSWORD}a"
request form_password_over_max 200 /long-invalid/_login \
    --data-urlencode username=admin --data-urlencode "password=${LONG_PASSWORD}a"
grep -q '密码无效' "$TEST_DIR/body" \
    && ok form_password_over_max_rejected || bad form_password_over_max_rejected missing present
request bearer_redirect 302 /index.html -H 'Authorization: Bearer opaque'
request basic_invalid_cookie 200 /index.html -u admin:admin123 -b auth_cookie=invalid
request basic_public 200 /public/index.html -u admin:wrong
request basic_deny_all 403 /deny/index.html -u admin:admin123
request basic_satisfy_any 200 /any/index.html -u admin:admin123
request basic_satisfy_any_invalid 401 /any/index.html -u admin:wrong
request browser_satisfy_any_allow 302 /allow/index.html
request basic_satisfy_any_allow_invalid 401 /allow/index.html -u admin:wrong
request basic_satisfy_any_allow_valid 200 /allow/index.html -u admin:admin123
request basic_native_module 200 /native/index.html -u admin:admin123
request basic_auth_request_denied 403 /check/index.html -u admin:admin123
request basic_other_user_file 401 /other/index.html -u admin:admin123
request basic_other_password 200 /other/index.html -u admin:changed123
request basic_redirect_other 401 /to-other/missing -u admin:admin123
request basic_redirect_public 200 /to-public/missing -u admin:admin123
grep -qx '/to-public/missing user=admin' "$TEST_DIR/access.log" \
    && ok redirect_identity || bad redirect_identity missing admin

# Cookie 会话和 Basic 认证共存，已建立的 Cookie 会话优先。
request form_login 302 /_login -c "$JAR" \
    -d 'username=admin&password=admin123&next=%2F'
request cookie_access 200 /index.html -b "$JAR"
request cookie_with_bad_basic 200 /index.html -b "$JAR" -u admin:wrong
request cookie_cross_origin_resource 200 /index.html -b "$JAR" -H 'Origin: null'
request cookie_with_bearer 200 /proxy/ -b "$JAR" -H 'Authorization: Bearer opaque'
eq cookie_proxy_identity "$(cat "$TEST_DIR/body")" 'GET|Bearer opaque|admin|'

# Basic 和网页登录共用令牌；认证成功退回预扣令牌，失败保留扣费。
request basic_success_index 200 /rate-basic/ -u admin:admin123
for i in 1 2 3; do
    request "basic_success_refunded_$i" 200 /rate-basic/index.html -u admin:admin123
done
request form_success_refunded 302 /rate-basic/_login \
    -d 'username=admin&password=admin123'
request basic_failure_consumes 401 /rate-basic/index.html -u admin:wrong
request basic_after_failure_limited 429 /rate-basic/index.html -u admin:admin123
request form_after_basic_failure 429 /rate-basic/_login \
    -d 'username=admin&password=admin123'
request cookie_after_basic_limit 200 /rate-basic/index.html -b "$JAR"
request form_failure_consumes 200 /rate-form/_login \
    -d 'username=admin&password=wrong'
request form_failure_limits_basic 429 /rate-form/index.html -u admin:admin123
request basic_rate_error 401 /rate-error/index.html -u admin:wrong
request basic_error_limits_valid 429 /rate-error/index.html -u admin:admin123
request basic_rate_malformed 401 /rate-malformed/index.html -H 'Authorization: Basic !!!'
request basic_malformed_limits_valid 429 /rate-malformed/index.html -u admin:admin123
request basic_rate_ip_success 200 /rate-ip/index.html -u admin:admin123
request form_rate_ip_success 302 /rate-ip/_login \
    -d 'username=admin&password=admin123'
request basic_rate_ip_success_again 200 /rate-ip/index.html -u admin:admin123
request basic_rate_ip_other_user 401 /rate-ip/index.html -u missing:admin123
request basic_rate_ip_limited 429 /rate-ip/index.html -u admin:admin123
request basic_rate_username_first 200 /rate-username/index.html -u admin:admin123
request basic_rate_username_other 401 /rate-username/index.html -u missing:admin123
request basic_rate_username_again 200 /rate-username/index.html -u admin:admin123
request basic_rate_username_failure 401 /rate-username/index.html -u admin:wrong
request basic_rate_username_limited 429 /rate-username/index.html -u admin:admin123
request basic_rate_missing_ip 400 /rate-trusted/index.html -u admin:admin123
request basic_rate_trusted_first 200 /rate-trusted/index.html -u admin:admin123 \
    -H 'X-Client-IP: 203.0.113.1'
request basic_rate_trusted_again 200 /rate-trusted/index.html -u admin:admin123 \
    -H 'X-Client-IP: 203.0.113.1'
request basic_rate_trusted_failure 401 /rate-trusted/index.html -u admin:wrong \
    -H 'X-Client-IP: 203.0.113.1'
request basic_rate_trusted_limited 429 /rate-trusted/index.html -u admin:admin123 \
    -H 'X-Client-IP: 203.0.113.1'
request basic_rate_trusted_other 200 /rate-trusted/index.html -u admin:admin123 \
    -H 'X-Client-IP: 203.0.113.2'

# 并发失败尝试预扣同一令牌，只有一个请求进入密码校验。
concurrent=$(python3 - "$PORT" <<'PY'
import base64, http.client, sys, threading
port = int(sys.argv[1])
auth = "Basic " + base64.b64encode(b"admin:wrong").decode()
codes = []
lock = threading.Lock()
def attempt():
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", "/rate-concurrent/index.html", headers={"Host": "localhost", "Authorization": auth})
    status = c.getresponse().status
    c.close()
    with lock:
        codes.append(status)
threads = [threading.Thread(target=attempt) for _ in range(8)]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
print("%d:%d:%d" % (codes.count(401), codes.count(429), len(codes)))
PY
)
eq concurrent_failures_reserved "$concurrent" "1:7:8"

# auth_cookie_basic off：Basic 头不参与认证和限流，按未认证请求跳转网页登录。
request basic_off_valid 302 /basic-off/index.html -u admin:admin123
grep -qi '^Location: .*/basic-off/_login?next=' "$TEST_DIR/headers" \
    && ok basic_off_login_location || bad basic_off_login_location missing present
request basic_off_invalid 302 /basic-off/index.html -u admin:wrong
request basic_off_cross_origin 302 /basic-off/index.html -u admin:admin123 -H 'Origin: null'
request basic_off_form_not_limited 200 /basic-off/_login \
    -d 'username=admin&password=wrong'
request basic_off_cookie 200 /basic-off/index.html -b "$JAR"

# auth_cookie_login_rate_refund off：认证成功同样保留扣费。
request norefund_basic_first 200 /rate-norefund/index.html -u admin:admin123
request norefund_basic_counted 429 /rate-norefund/index.html -u admin:admin123
request norefund_form_shared 429 /rate-norefund/_login \
    -d 'username=admin&password=admin123'
request norefund_form_first 302 /rate-norefund-form/_login \
    -d 'username=admin&password=admin123'
request norefund_form_counted 429 /rate-norefund-form/_login \
    -d 'username=admin&password=admin123'
request basic_rate_untrusted 400 /rate-untrusted/index.html -u admin:admin123 \
    -H 'X-Client-IP: 203.0.113.1'

# 缺少密码和 CSRF 失败与表单相同，只消耗来源 IP 桶。
request basic_empty_rate 401 /rate-empty/index.html -u admin:
request form_after_basic_empty 302 /rate-empty/_login \
    -d 'username=admin&password=admin123'
request basic_csrf_rate 400 /rate-csrf/index.html -u admin:admin123 -H 'Origin: null'
request form_after_basic_csrf 302 /rate-csrf/_login \
    -d 'username=admin&password=admin123'
request basic_bad_user_rate 401 /rate-bad-user/index.html \
    -H "Authorization: Basic $(printf 'admin\rname:admin123' | openssl base64 -A)"
request form_after_basic_bad_user 429 /rate-bad-user/_login \
    -d 'username=admin%0Dname&password=admin123'

request logout 302 /_logout -b "$JAR" -c "$JAR" -d ''
request after_logout 302 /index.html -b "$JAR"

# 用户文件的修改在 reload 后对 Basic 生效，与网页登录使用同一快照。
cp "$TEST_DIR/other" "$TEST_DIR/htpasswd"
request basic_before_reload 200 /index.html -u admin:admin123
"$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf" -s reload
attempt=0
while [ "$attempt" -lt 50 ]; do
    code=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' \
        -u admin:changed123 "$BASE/index.html")
    [ "$code" = 200 ] && break
    attempt=$((attempt + 1))
    sleep 0.1
done
request basic_old_password_after_reload 401 /index.html -u admin:admin123
request basic_new_password_after_reload 200 /index.html -u admin:changed123

echo "auth_cookie basic: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
