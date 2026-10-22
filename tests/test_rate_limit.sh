#!/bin/sh
# 登录限流集成测试：默认令牌、继承、三种统计键、可信 Header、多 worker、认证域隔离、双共享区、reload 和 LRU。
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 /path/to/nginx" >&2
    exit 2
fi

NGX_BIN=$(realpath "$1")
PORT=${PORT:-18126}
TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/auth-cookie-rate.XXXXXX")
unset NGINX
PASS=0
FAIL=0

cleanup() {
    if [ -f "$TEST_DIR/nginx.pid" ]; then
        "$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf" -s quit \
            >/dev/null 2>&1 || true
        sleep 0.2
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

mkdir -p "$TEST_DIR/www" "$TEST_DIR/logs" "$TEST_DIR/client_body_temp"
chmod 755 "$TEST_DIR" "$TEST_DIR/www" "$TEST_DIR/logs"
printf '%s\n' 'protected' > "$TEST_DIR/www/index.html"
printf 'user1:%s\nuser2:%s\n' \
    "$(openssl passwd -apr1 -salt testsalt pass123)" \
    "$(openssl passwd -apr1 -salt testsalt otherpass)" \
    > "$TEST_DIR/htpasswd"

server_block() {
    port=$1
    shift
    cat <<EOF
    server {
        listen 127.0.0.1:$port;
        server_name localhost;
        auth_cookie_user_file $TEST_DIR/htpasswd;
        auth_cookie_secret $TEST_DIR/secret;
        auth_cookie_secure off;
        $*
        location / { root $TEST_DIR/www; index index.html; }
    }
EOF
}

write_conf() {
    size=${1:-32768}
    cat > "$TEST_DIR/nginx.conf" <<EOF
worker_processes 2;
error_log $TEST_DIR/error.log notice;
pid $TEST_DIR/nginx.pid;
daemon on;
events { worker_connections 512; }
http {
    access_log $TEST_DIR/access.log;
    log_format ratepid '\$pid';
    client_body_temp_path $TEST_DIR/client_body_temp;
    proxy_temp_path $TEST_DIR/proxy_temp;
    fastcgi_temp_path $TEST_DIR/fastcgi_temp;
    uwsgi_temp_path $TEST_DIR/uwsgi_temp;
    scgi_temp_path $TEST_DIR/scgi_temp;
    auth_cookie_login_rate_zone_size $size;
$(server_block $PORT)
$(server_block $((PORT + 1)) 'auth_cookie_login_rate off;')
$(server_block $((PORT + 2)) 'auth_cookie_login_rate 1 60s 1 60s;')
$(server_block $((PORT + 3)) 'auth_cookie_login_rate 1 60s 1 60s; auth_cookie_login_rate_key username;')
$(server_block $((PORT + 4)) 'auth_cookie_login_rate 1 60s 1 60s;')
$(server_block $((PORT + 5)) 'auth_cookie_login_rate 1 60s 1 60s; auth_cookie_login_rate_trusted_proxy 127.0.0.1;')
$(server_block $((PORT + 6)) 'auth_cookie_login_rate 1 60s 1 60s; auth_cookie_login_rate_trusted_proxy 127.0.0.1; auth_cookie_login_rate_ip_header X-Forwarded-For X-Missing X-Client-IP; auth_cookie_login_rate_ip_header X-Fallback-IP;')
$(server_block $((PORT + 7)) 'auth_cookie_login_rate 1 60s 1 60s; auth_cookie_login_rate_trusted_proxy 203.0.113.10; auth_cookie_login_rate_ip_header X-Client-IP;')
$(server_block $((PORT + 8)) 'auth_cookie_login_rate 1 60s 1 60s; auth_cookie_login_rate_trusted_proxy 127.0.0.1;')
$(server_block $((PORT + 9)) 'set_real_ip_from 127.0.0.1; real_ip_header X-Real-IP; auth_cookie_login_rate 1 60s 1 60s;')
$(server_block $((PORT + 10)) 'auth_cookie_login_rate 1 60s 1 60s; location = /_login { auth_cookie_login_rate off; }')
$(server_block $((PORT + 11)) 'auth_cookie_login_rate 1 60s 1 60s; location = /_login { auth_cookie_login_rate 2 60s 2 60s; }')
$(server_block $((PORT + 12)) 'auth_cookie_login_rate 1 60s 1 60s; auth_cookie_login_rate_trusted_proxy 127.0.0.1; auth_cookie_login_rate_ip_header X-Parent-IP; location = /_login { auth_cookie_login_rate_ip_header X-Child-IP; }')
$(server_block $((PORT + 13)) 'auth_cookie_login_rate 1 60s 1 60s; auth_cookie_login_rate_trusted_proxy 127.0.0.1; auth_cookie_login_rate_ip_header X-Duplicate-IP X-Fallback-IP;')
$(server_block $((PORT + 14)) 'auth_cookie_login_rate 1 3600s 1 3600s; auth_cookie_login_rate_trusted_proxy 127.0.0.1;')
$(server_block $((PORT + 15)) 'auth_cookie_login_rate 5 3000ms 5 3000ms;')
$(server_block $((PORT + 16)) 'auth_cookie_login_rate 1 60s 1 60s; auth_cookie_logout_uri /_logout;')
$(server_block $((PORT + 17)) 'auth_cookie_login_rate 1 60s 1 60s; auth_cookie_login_rate_key ip_username;')
$(server_block $((PORT + 18)) 'auth_cookie_login_rate 1 60s 1 60s; auth_cookie_login_rate_trusted_proxy 127.0.0.1; auth_cookie_login_rate_ip_header X-Parent-IP; location = /_login { auth_cookie_login_rate_ip_header off; auth_cookie_login_rate_trusted_proxy off; }')
$(server_block $((PORT + 19)) 'auth_cookie_login_rate 1 60s 1 60s;')
$(server_block $((PORT + 20)) 'access_log logs/ratepid.log ratepid; auth_cookie_login_rate 1 60s 1 60s; auth_cookie_login_rate_trusted_proxy 127.0.0.1;')
$(server_block $((PORT + 21)) 'auth_cookie_login_rate 1 60s 1 60s; auth_cookie_login_rate_trusted_proxy 127.0.0.1;')
$(server_block $((PORT + 22)) 'auth_cookie_login_rate 1 60s 1 60s; auth_cookie_login_rate_trusted_proxy 127.0.0.1;')
$(server_block $((PORT + 23)) 'auth_cookie_login_rate 1 3600s 1 3600s; auth_cookie_login_rate_key ip_username; auth_cookie_login_rate_trusted_proxy 127.0.0.1;')
$(server_block $((PORT + 24)) 'auth_cookie_login_rate 1 3600s 1 3600s; auth_cookie_login_rate_key username; auth_cookie_login_rate_trusted_proxy 127.0.0.1;')
$(server_block $((PORT + 25)) 'auth_cookie_login_rate 3 60s 1 60s; auth_cookie_login_rate_key ip_username;')
$(server_block $((PORT + 26)) 'auth_cookie_login_rate 1 60s 1 60s; auth_cookie_login_rate_key username;')
$(server_block $((PORT + 27)) 'auth_cookie_login_rate 10 3600s 1 3600s; auth_cookie_login_rate_key ip_username;')
$(server_block $((PORT + 28)) 'auth_cookie_login_rate 1 60s 1 60s; auth_cookie_login_rate_key username;')
$(server_block $((PORT + 29)) 'auth_cookie_login_rate 1 10s 1 10s; auth_cookie_login_rate_key ip;')
    server {
        listen unix:$TEST_DIR/trusted.sock;
        auth_cookie_user_file $TEST_DIR/htpasswd;
        auth_cookie_secret $TEST_DIR/secret;
        auth_cookie_secure off;
        auth_cookie_login_rate 1 60s 1 60s;
        auth_cookie_login_rate_trusted_proxy unix:;
    }
    server {
        listen unix:$TEST_DIR/untrusted.sock;
        auth_cookie_user_file $TEST_DIR/htpasswd;
        auth_cookie_secret $TEST_DIR/secret;
        auth_cookie_secure off;
        auth_cookie_login_rate 1 60s 1 60s;
    }
}
EOF
}

config_fails() {
    name=$1
    http_extra=$2
    server_extra=$3
    cat > "$TEST_DIR/invalid.conf" <<EOF
worker_processes 1;
error_log $TEST_DIR/invalid.log notice;
pid $TEST_DIR/invalid.pid;
events { worker_connections 32; }
http {
    access_log $TEST_DIR/invalid-access.log;
    $http_extra
    server {
        listen 127.0.0.1:1;
        auth_cookie_user_file $TEST_DIR/htpasswd;
        auth_cookie_secret $TEST_DIR/secret;
        auth_cookie_secure off;
        $server_extra
        location / { return 404; }
    }
}
EOF
    if "$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/invalid.conf" -t >/dev/null 2>&1; then
        bad "$name" "accepted" "rejected"
    else
        ok "$name"
    fi
}

start_nginx() {
    "$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf" -t
    "$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf"
    sleep 0.3
}

post() {
    port=$1
    body=$2
    shift 2
    curl -sS -o /dev/null -w '%{http_code}' -H 'Host: localhost' "$@" \
        -d "$body" "http://127.0.0.1:$port/_login"
}

# 单进程连续请求，避免逐个启动 curl 的耗时触发毫秒级令牌补充。
post_fast() {
    port=$1
    body=$2
    count=$3
    url="http://127.0.0.1:$port/_login"
    set --
    i=1
    while [ "$i" -le "$count" ]; do
        set -- "$@" -H 'Host: localhost' -d "$body" -o /dev/null \
            -w '%{http_code}\n' "$url"
        if [ "$i" -lt "$count" ]; then
            set -- "$@" --next
        fi
        i=$((i + 1))
    done
    curl -sS "$@"
}

# 单进程模拟同一 NAT 出口下的不同用户。
post_fast_users() {
    port=$1
    count=$2
    prefix=$3
    url="http://127.0.0.1:$port/_login"
    set --
    i=1
    while [ "$i" -le "$count" ]; do
        set -- "$@" -H 'Host: localhost' \
            -d "username=$prefix$i&password=wrong" -o /dev/null \
            -w '%{http_code}\n' "$url"
        if [ "$i" -lt "$count" ]; then
            set -- "$@" --next
        fi
        i=$((i + 1))
    done
    curl -sS "$@"
}

config_fails "config_header_requires_proxy" "" "auth_cookie_login_rate_ip_header X-Client-IP;"
config_fails "config_off_mixed_with_value" "" "auth_cookie_login_rate_trusted_proxy off 127.0.0.1;"
config_fails "config_duplicate_zone_size" "auth_cookie_login_rate_zone_size 32k; auth_cookie_login_rate_zone_size 64k;" ""
config_fails "config_two_args_rejected" "" "auth_cookie_login_rate 1 60s;"
config_fails "config_invalid_key" "" "auth_cookie_login_rate_key user;"

write_conf 32768
start_nginx

# 默认 ip_username：同一 NAT 出口允许 10 个不同用户突发，第 11 个触发 IP 桶。
eq "default_get_not_counted_1" "$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:$PORT/_login)" "200"
eq "default_get_not_counted_2" "$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:$PORT/_login)" "200"
eq "default_head_not_counted_1" "$(curl -sS -I -o /dev/null -w '%{http_code}' http://127.0.0.1:$PORT/_login)" "200"
eq "default_head_not_counted_2" "$(curl -sS -I -o /dev/null -w '%{http_code}' http://127.0.0.1:$PORT/_login)" "200"
codes=$(post_fast_users $PORT 11 nat)
i=1
for code in $codes; do
    if [ "$i" -le 10 ]; then
        eq "default_nat_user_$i" "$code" "200"
    else
        eq "default_nat_user_11_ip_limited" "$code" "429"
    fi
    i=$((i + 1))
done
sleep 1.1
eq "default_same_user_refill" "$(post $PORT 'username=nat1&password=wrong')" "200"
eq "default_same_user_limited" "$(post $PORT 'username=nat1&password=wrong')" "429"

# 显式 off 保持原有连续登录行为。
i=1
while [ "$i" -le 3 ]; do
    eq "rate_off_$i" "$(post $((PORT + 1)) 'username=user1&password=wrong')" "200"
    i=$((i + 1))
done

# 登录前的 CSRF、空表单和过大请求体也消耗令牌。
eq "csrf_failure_consumes" "$(post $((PORT + 2)) 'username=user1&password=wrong' -H 'Origin: https://attacker.invalid')" "400"
eq "after_csrf_failure_limited" "$(post $((PORT + 2)) 'username=user1&password=wrong')" "429"

# ip 键下，两个用户名共享同一来源额度。
eq "ip_user1_allowed" "$(post $((PORT + 2)) 'username=user1&password=wrong')" "429"
eq "ip_user2_same_bucket" "$(post $((PORT + 2)) 'username=user2&password=wrong')" "429"

# username 键下，不同用户名独立，重复同一用户名被限制。
eq "username_user1" "$(post $((PORT + 3)) 'username=user1&password=wrong')" "200"
eq "username_user2" "$(post $((PORT + 3)) 'username=user2&password=wrong')" "200"
eq "username_user1_limited" "$(post $((PORT + 3)) 'username=user1&password=wrong')" "429"

# 默认可信代理为空，伪造 XFF 不改变来源额度。
eq "untrusted_xff_first" "$(post $((PORT + 4)) 'x=1' -H 'X-Forwarded-For: 203.0.113.1')" "200"
eq "untrusted_xff_second" "$(post $((PORT + 4)) 'x=1' -H 'X-Forwarded-For: 203.0.113.2')" "429"

# 可信代理下 auto 依次解析 XFF，并按该地址共享额度。
eq "trusted_xff_first" "$(post $((PORT + 5)) 'x=1' -H 'X-Forwarded-For: 203.0.113.11')" "200"
eq "trusted_xff_limited" "$(post $((PORT + 5)) 'x=1' -H 'X-Forwarded-For: 203.0.113.11')" "429"
eq "trusted_xff_other_ip" "$(post $((PORT + 5)) 'x=1' -H 'X-Forwarded-For: 203.0.113.12')" "200"
eq "auto_bad_xff_uses_real_ip" "$(post $((PORT + 5)) 'x=1' -H 'X-Forwarded-For: invalid' -H 'X-Real-IP: 203.0.113.13')" "200"
eq "auto_bad_xff_real_ip_limited" "$(post $((PORT + 5)) 'x=1' -H 'X-Forwarded-For: invalid' -H 'X-Real-IP: 203.0.113.13')" "429"

# IPv6 同 /64 聚合，映射地址与 IPv4 计入同一键。
eq "ipv6_first" "$(post $((PORT + 5)) 'x=1' -H 'X-Forwarded-For: 2001:db8:1:2::1')" "200"
eq "ipv6_same_prefix" "$(post $((PORT + 5)) 'x=1' -H 'X-Forwarded-For: 2001:db8:1:2::2')" "429"
eq "ipv6_other_prefix" "$(post $((PORT + 5)) 'x=1' -H 'X-Forwarded-For: 2001:db8:1:3::1')" "200"
eq "mapped_ipv4_first" "$(post $((PORT + 5)) 'x=1' -H 'X-Forwarded-For: ::ffff:192.0.2.12')" "200"
eq "mapped_ipv4_same_bucket" "$(post $((PORT + 5)) 'x=1' -H 'X-Forwarded-For: 192.0.2.12')" "429"

for trust in trusted untrusted; do
    first=$(curl -sS --unix-socket "$TEST_DIR/$trust.sock" -o /dev/null \
        -w '%{http_code}' -d 'x=1' -H 'X-Forwarded-For: 192.0.2.21' http://localhost/_login)
    second=$(curl -sS --unix-socket "$TEST_DIR/$trust.sock" -o /dev/null \
        -w '%{http_code}' -d 'x=1' -H 'X-Forwarded-For: 192.0.2.22' http://localhost/_login)
    eq "unix_${trust}_first" "$first" "200"
    if [ "$trust" = trusted ]; then expected=200; else expected=429; fi
    eq "unix_${trust}_second" "$second" "$expected"
done

# 高频拒绝仍积累回填时间，不要求客户端暂停重试。
allowed=$(python3 - "$((PORT + 29))" <<'PY'
import http.client, sys, time
c = http.client.HTTPConnection("127.0.0.1", int(sys.argv[1]), timeout=5)
end = time.monotonic() + 11
allowed = 0
while time.monotonic() < end:
    c.request("POST", "/_login", "x=1", {"Content-Type": "application/x-www-form-urlencoded"})
    response = c.getresponse()
    response.read()
    assert response.status in (200, 429), response.status
    allowed += response.status == 200
    time.sleep(0.003)
c.close()
print(allowed)
PY
)
eq "frequent_requests_refill" "$allowed" "2"

# 显式 Header 按声明顺序尝试；缺失或非法时继续后续 Header。
eq "header_order_first" "$(post $((PORT + 6)) 'x=1' -H 'X-Client-IP: 203.0.113.21')" "200"
eq "header_order_limited" "$(post $((PORT + 6)) 'x=1' -H 'X-Client-IP: 203.0.113.21')" "429"
eq "header_first_valid_stops" "$(post $((PORT + 6)) 'x=1' -H 'X-Client-IP: 203.0.113.21' -H 'X-Fallback-IP: 203.0.113.23')" "429"
eq "header_invalid_then_fallback" "$(post $((PORT + 6)) 'x=1' -H 'X-Client-IP: invalid' -H 'X-Fallback-IP: 203.0.113.22')" "200"
eq "malformed_xff_fallback_first" "$(post $((PORT + 6)) 'x=1' -H 'X-Forwarded-For: invalid' -H 'X-Fallback-IP: 203.0.113.24')" "200"
eq "malformed_xff_fallback_other" "$(post $((PORT + 6)) 'x=1' -H 'X-Forwarded-For: invalid' -H 'X-Fallback-IP: 203.0.113.25')" "200"

# 显式 Header 要求直接连接属于可信代理，否则 400。
eq "explicit_header_untrusted" "$(post $((PORT + 7)) 'x=1' -H 'X-Client-IP: 203.0.113.23')" "400"

# XFF 地址链从右向左找第一个不可信地址，而不是取最左侧。
eq "xff_right_chain_first" "$(post $((PORT + 8)) 'x=1' -H 'X-Forwarded-For: 198.51.100.1, 203.0.113.31')" "200"
eq "xff_right_chain_same" "$(post $((PORT + 8)) 'x=1' -H 'X-Forwarded-For: 198.51.100.2, 203.0.113.31')" "429"

# realip 已经改写地址时，直接使用其结果。
eq "realip_first" "$(post $((PORT + 9)) 'x=1' -H 'X-Real-IP: 203.0.113.41')" "200"
eq "realip_limited" "$(post $((PORT + 9)) 'x=1' -H 'X-Real-IP: 203.0.113.41')" "429"

# 子层级可关闭或替换继承的限流参数。
eq "child_off_first" "$(post $((PORT + 10)) 'x=1')" "200"
eq "child_off_second" "$(post $((PORT + 10)) 'x=1')" "200"
eq "child_override_first" "$(post $((PORT + 11)) 'x=1')" "200"
eq "child_override_second" "$(post $((PORT + 11)) 'x=1')" "200"
eq "child_override_limited" "$(post $((PORT + 11)) 'x=1')" "429"

# 子层级的 Header 列表整体替换父层级，父 Header 不再被识别。
eq "child_header_replaces_parent" "$(post $((PORT + 12)) 'x=1' -H 'X-Parent-IP: 203.0.113.51')" "400"

# 同名普通 Header 出现多次时跳过该 Header，继续后续候选。
eq "duplicate_header_fallback_first" "$(post $((PORT + 13)) 'x=1' -H 'X-Duplicate-IP: 203.0.113.61' -H 'X-Duplicate-IP: 203.0.113.62' -H 'X-Fallback-IP: 203.0.113.63')" "200"
eq "duplicate_header_fallback_limited" "$(post $((PORT + 13)) 'x=1' -H 'X-Fallback-IP: 203.0.113.63')" "429"

# 容量 5、周期 3000ms：允许 5 次突发，600ms 后恢复约一个令牌。
codes=$(post_fast $((PORT + 15)) 'x=1' 6)
i=1
for code in $codes; do
    if [ "$i" -le 5 ]; then
        eq "burst_5_$i" "$code" "200"
    else
        eq "burst_5_limited" "$code" "429"
    fi
    i=$((i + 1))
done
sleep 0.7
eq "burst_fractional_refill" "$(post $((PORT + 15)) 'x=1')" "200"

# 登录成功退回预扣令牌；失败保留扣费，额度耗尽后正确密码同样受限。
eq "success_refunded_first" "$(post $((PORT + 16)) 'username=user1&password=pass123')" "302"
eq "success_refunded_second" "$(post $((PORT + 16)) 'username=user1&password=pass123')" "302"
eq "failure_after_success_consumes" "$(post $((PORT + 16)) 'username=user1&password=wrong')" "200"
eq "success_after_failure_limited" "$(post $((PORT + 16)) 'username=user1&password=pass123')" "429"

# 登出 POST 不消耗令牌；登录桶耗尽后登出仍可用。
eq "logout_post_not_counted" "$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: localhost' -d '' http://127.0.0.1:$((PORT + 16))/_logout)" "302"

# ip_username 模式下，无效用户名回退到 IP 键并计入请求。
eq "invalid_username_ip_key_first" "$(post $((PORT + 17)) 'username=bad%3Auser&password=wrong')" "200"
eq "invalid_username_ip_key_limited" "$(post $((PORT + 17)) 'username=bad%3Auser&password=wrong')" "429"

# 两级模式先消耗 IP 令牌；重复用户名触发 IP+用户名桶，轮换用户名最终触发 IP 桶。
eq "hierarchy_user1_first" "$(post $((PORT + 25)) 'username=user1&password=wrong')" "200"
eq "hierarchy_user1_limited" "$(post $((PORT + 25)) 'username=user1&password=wrong')" "429"
eq "hierarchy_user2_allowed" "$(post $((PORT + 25)) 'username=user2&password=wrong')" "200"
eq "hierarchy_user3_ip_limited" "$(post $((PORT + 25)) 'username=other&password=wrong')" "429"

# username 模式下，无法获得有效用户名时同样回退到 IP 键。
eq "username_invalid_ip_key_first" "$(post $((PORT + 26)) 'username=bad%3Auser&password=wrong')" "200"
eq "username_invalid_ip_key_limited" "$(post $((PORT + 26)) 'username=bad%3Auser&password=wrong')" "429"

# username 模式下，CSRF 失败无法取得用户名，也回退到 IP 键。
eq "username_csrf_first" "$(post $((PORT + 28)) 'username=user1&password=wrong' -H 'Origin: https://attacker.invalid')" "400"
eq "username_csrf_ip_limited" "$(post $((PORT + 28)) 'username=user2&password=wrong' -H 'Origin: https://attacker.invalid')" "429"

# 子层级清空两个继承列表后回到 auto；无可信代理时伪造 Header 不改变来源。
eq "child_lists_off_first" "$(post $((PORT + 18)) 'x=1' -H 'X-Parent-IP: 203.0.113.71' -H 'X-Forwarded-For: 203.0.113.72')" "200"
eq "child_lists_off_limited" "$(post $((PORT + 18)) 'x=1' -H 'X-Parent-IP: 203.0.113.73' -H 'X-Forwarded-For: 203.0.113.74')" "429"

# 结束首个请求所属 worker 后，第二个请求必定由其他 worker 处理；额度仍共享。
eq "multi_worker_first" "$(post $((PORT + 20)) 'x=1' -H 'X-Forwarded-For: 203.0.113.81')" "200"
worker_pid=$(tail -n 1 "$TEST_DIR/logs/ratepid.log" 2>/dev/null || true)
if [ -n "$worker_pid" ] && kill -0 "$worker_pid" 2>/dev/null; then
    master_pid=$(cat "$TEST_DIR/nginx.pid")
    kill -TERM "$worker_pid"
    i=0
    while [ "$i" -lt 50 ]; do
        workers=$(pgrep -P "$master_pid" 2>/dev/null | wc -l)
        [ "$workers" -ge 2 ] && break
        sleep 0.1
        i=$((i + 1))
    done
    eq "multi_worker_other_worker_limited" "$(post $((PORT + 20)) 'x=1' -H 'X-Forwarded-For: 203.0.113.81')" "429"
else
    bad "multi_worker_worker_pid" "$worker_pid" "live worker pid"
fi

# 认证域按最终 server/location 配置隔离，相同客户端在其他认证域仍有独立额度。
eq "scope_first_server" "$(post $((PORT + 21)) 'x=1' -H 'X-Forwarded-For: 203.0.113.82')" "200"
eq "scope_second_server_independent" "$(post $((PORT + 22)) 'x=1' -H 'X-Forwarded-For: 203.0.113.82')" "200"
eq "scope_first_server_limited" "$(post $((PORT + 21)) 'x=1' -H 'X-Forwarded-For: 203.0.113.82')" "429"

# IP+用户名区的大量新条目不会淘汰 IP 区；IP 总限额不会被用户名轮换重置。
eq "zone_isolation_ip_first" "$(post $((PORT + 23)) 'username=user1&password=wrong' -H 'X-Forwarded-For: 203.0.113.91')" "200"
i=0
while [ "$i" -lt 1400 ]; do
    code=$(post $((PORT + 24)) "username=rotated$i&password=wrong" -H "X-Forwarded-For: 198.18.$((i / 256)).$((i % 256))")
    if [ "$code" != 200 ]; then
        bad "username_zone_fill_$i" "$code" "200"
        break
    fi
    i=$((i + 1))
done
[ "$i" -eq 1400 ] && ok "username_zone_fill_1400"
eq "zone_isolation_ip_kept" "$(post $((PORT + 23)) 'username=user2&password=wrong' -H 'X-Forwarded-For: 203.0.113.91')" "429"

# 避免默认桶的毫秒恢复时间影响后续 reload 断言。
sleep 1.1

# 同大小 reload 复用两个共享内存区，IP 桶和 IP+用户名桶状态都保留。
eq "reload_preserve_first" "$(post $((PORT + 19)) 'x=1')" "200"
eq "reload_preserve_before" "$(post $((PORT + 19)) 'x=1')" "429"
eq "reload_username_first" "$(post $((PORT + 27)) 'username=user1&password=wrong')" "200"
"$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf" -s reload
sleep 0.5
eq "reload_same_size_keeps_state" "$(post $((PORT + 19)) 'x=1')" "429"
eq "reload_username_keeps_state" "$(post $((PORT + 27)) 'username=user1&password=wrong')" "429"
eq "reload_username_ip_bucket_available" "$(post $((PORT + 27)) 'username=user2&password=wrong')" "200"

# 共享内存大小改变后由 Nginx 原生机制创建新区域，状态清空。
write_conf 65536
"$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf" -s reload
sleep 0.5
eq "reload_size_change_resets" "$(post $((PORT + 19)) 'x=1')" "200"

# 完整重启清空共享内存。
"$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf" -s quit
sleep 0.4
start_nginx
eq "restart_clears_state" "$(post $((PORT + 19)) 'x=1')" "200"

# 小共享区在大量不同来源下执行 LRU 淘汰，最早来源可再次获得新桶。
i=0
while [ "$i" -lt 1400 ]; do
    code=$(post $((PORT + 14)) 'x=1' -H "X-Forwarded-For: 198.51.$((i / 256)).$((i % 256))")
    if [ "$code" != 200 ]; then
        bad "zone_fill_$i" "$code" "200"
        break
    fi
    i=$((i + 1))
done
[ "$i" -eq 1400 ] && ok "zone_fill_1400"
eq "zone_lru_reuses_oldest" "$(post $((PORT + 14)) 'x=1' -H 'X-Forwarded-For: 198.51.0.0')" "200"

echo "---- summary PASS=$PASS FAIL=$FAIL ----"
[ "$FAIL" -eq 0 ]
