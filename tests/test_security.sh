#!/bin/sh
# 安全回归测试:覆盖 AC-01 请求边界、AC-02 联合访问控制、AC-03 重定向、
# AC-04 CSRF 同源校验、AC-07 编码路径回跳。
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 /path/to/nginx" >&2
    exit 2
fi

NGX_BIN=$(realpath "$1")
PORT=${PORT:-18110}
TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/auth-cookie-security.XXXXXX")
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
printf 'user1:%s\n' "$(openssl passwd -apr1 -salt testsalt pass123)" \
    > "$TEST_DIR/htpasswd"

# server1: 主测试(absolute_redirect off 观察原始 Location)
# server2: satisfy all + deny all(联合访问控制)
# server3: auth_cookie_csrf off(关闭同源校验)
cat > "$TEST_DIR/nginx.conf" <<EOF
worker_processes 1;
error_log $TEST_DIR/error.log notice;
pid $TEST_DIR/nginx.pid;
daemon on;

events { worker_connections 128; }

http {
    access_log $TEST_DIR/access.log;
    client_body_temp_path $TEST_DIR/client_body_temp;
    proxy_temp_path $TEST_DIR/proxy_temp;
    fastcgi_temp_path $TEST_DIR/fastcgi_temp;
    uwsgi_temp_path $TEST_DIR/uwsgi_temp;
    scgi_temp_path $TEST_DIR/scgi_temp;

    server {
        listen 127.0.0.1:$PORT;
        server_name app.test;
        absolute_redirect off;

        auth_cookie_user_file $TEST_DIR/htpasswd;
        auth_cookie_secret $TEST_DIR/secret;
        auth_cookie_secure off;
        auth_cookie_login_rate off;
        auth_cookie_logout_uri /_logout;

        location / {
            root $TEST_DIR/www;
            index index.html;
        }
    }

    server {
        listen 127.0.0.1:$((PORT + 1));
        server_name app.test;

        satisfy all;
        deny all;

        auth_cookie_user_file $TEST_DIR/htpasswd;
        auth_cookie_secret $TEST_DIR/secret;
        auth_cookie_secure off;
        auth_cookie_login_rate off;

        location / {
            root $TEST_DIR/www;
            index index.html;
        }
    }

    server {
        listen 127.0.0.1:$((PORT + 2));
        server_name app.test;
        absolute_redirect off;

        auth_cookie_user_file $TEST_DIR/htpasswd;
        auth_cookie_secret $TEST_DIR/secret;
        auth_cookie_secure off;
        auth_cookie_login_rate off;
        auth_cookie_csrf off;

        location / {
            root $TEST_DIR/www;
            index index.html;
        }
    }
    server {
        listen 127.0.0.1:$((PORT + 3));
        auth_cookie_user_file $TEST_DIR/htpasswd;
        auth_cookie_secret $TEST_DIR/secret;
        auth_cookie_name __Host-auth_cookie;
        auth_cookie_secure on;
        auth_cookie_login_rate off;
    }
}
EOF

"$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf" -t
"$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf"
sleep 0.3

BASE="http://127.0.0.1:$PORT"
BASE_DENY="http://127.0.0.1:$((PORT + 1))"
BASE_NOCSRF="http://127.0.0.1:$((PORT + 2))"
LOGIN_BODY='username=user1&password=pass123&next=%2F'

# ---------- AC-01: GET/HEAD 登录页带 body,body 不能被解析为下一条请求 ----------
python3 - "$PORT" "$TEST_DIR" <<'PY'
import socket, sys, re

port = int(sys.argv[1])
out = open(sys.argv[2] + "/ac01.out", "w")

for method in ("GET", "HEAD"):
    inner = (b"GET /_login?embedded=1 HTTP/1.1\r\n"
             b"Host: app.test\r\nConnection: close\r\n\r\n")
    raw = (f"{method} /_login HTTP/1.1\r\n"
           f"Host: app.test\r\n"
           f"Content-Length: {len(inner)}\r\n"
           f"Connection: keep-alive\r\n\r\n").encode() + inner
    s = socket.create_connection(("127.0.0.1", port), 3)
    s.settimeout(2)
    s.sendall(raw)
    data = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    s.close()
    statuses = re.findall(rb"HTTP/1.1 ([0-9]{3})", data)
    out.write("%s:%s\n" % (method, ",".join(s.decode() for s in statuses)))
out.close()
PY

for m in GET HEAD; do
    got=$(grep "^$m:" "$TEST_DIR/ac01.out" | cut -d: -f2)
    eq "ac01_${m}_body_not_reparsed" "$got" "200"
done

# ---------- AC-02: satisfy all + deny all 下登录入口被拒绝 ----------
code=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: app.test' \
    "$BASE_DENY/_login")
eq "ac02_deny_login_page_403" "$code" "403"

hdr=$(curl -sS -D - -o /dev/null -w '' -H 'Host: app.test' \
    -d "$LOGIN_BODY" "$BASE_DENY/_login")
code=$(printf '%s' "$hdr" | head -1 | awk '{print $2}')
eq "ac02_deny_login_post_403" "$code" "403"
case "$hdr" in
    *Set-Cookie:*|*set-cookie:*) bad "ac02_deny_no_cookie" "set" "none" ;;
    *) ok "ac02_deny_no_cookie" ;;
esac

# 主 server 登录入口不受影响
code=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: app.test' \
    "$BASE/_login")
eq "ac02_normal_login_page_200" "$code" "200"

# ---------- AC-03: 同 Host 绝对 URL 的双斜杠 path 被拒绝,回退兜底 ----------
hdr=$(curl -sS -D - -o /dev/null -H 'Host: app.test' \
    --data '' "$BASE/_logout?next=https%3A%2F%2Fapp.test%2F%2Fevil.test%2F")
loc=$(printf '%s' "$hdr" | awk 'tolower($1)=="location:" {print $2}' | tr -d '\r')
eq "ac03_double_slash_rejected" "$loc" "/_login"

# 合法同 Host 绝对 URL 仍保留
hdr=$(curl -sS -D - -o /dev/null -H 'Host: app.test' \
    --data '' "$BASE/_logout?next=https%3A%2F%2Fapp.test%2Fprivate")
loc=$(printf '%s' "$hdr" | awk 'tolower($1)=="location:" {print $2}' | tr -d '\r')
eq "ac03_valid_absolute_kept" "$loc" "/private"

# 直接协议相对路径仍拒绝
hdr=$(curl -sS -D - -o /dev/null -H 'Host: app.test' \
    --data '' "$BASE/_logout?next=%2F%2Fevil.test%2F")
loc=$(printf '%s' "$hdr" | awk 'tolower($1)=="location:" {print $2}' | tr -d '\r')
eq "ac03_protocol_relative_rejected" "$loc" "/_login"

hdr=$(curl -sS -D - -o /dev/null -H 'Host: app.test' --data '' \
    "$BASE/_logout?next=https%3A%2F%2Fapp.test%252Fa%2F%2Fevil.test%2F")
loc=$(printf '%s' "$hdr" | awk 'tolower($1)=="location:" {print $2}' | tr -d '\r')
eq "ac03_encoded_authority_rejected" "$loc" "/_login"

# ---------- AC-04: CSRF 同源校验 ----------
# 跨站 Origin 登录被拒绝
hdr=$(curl -sS -D - -o /dev/null -H 'Host: app.test' \
    -H 'Origin: https://attacker.invalid' \
    -d "$LOGIN_BODY" "$BASE/_login")
code=$(printf '%s' "$hdr" | head -1 | awk '{print $2}')
eq "ac04_cross_site_login_400" "$code" "400"
case "$hdr" in
    *Set-Cookie:*|*set-cookie:*) bad "ac04_cross_site_no_cookie" "set" "none" ;;
    *) ok "ac04_cross_site_no_cookie" ;;
esac

# 同源 Origin(忽略 scheme)登录成功
code=$(curl -sS -o /dev/null -c "$TEST_DIR/cookies" -w '%{http_code}' \
    -H 'Host: app.test' -H 'Origin: http://app.test' \
    -d "$LOGIN_BODY" "$BASE/_login")
eq "ac04_same_host_login_302" "$code" "302"

# 无 Origin 的 curl 客户端不受影响
code=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: app.test' \
    -d "$LOGIN_BODY" "$BASE/_login")
eq "ac04_no_origin_login_302" "$code" "302"

# 无 Origin 但 Sec-Fetch-Site: cross-site 拒绝
code=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: app.test' \
    -H 'Sec-Fetch-Site: cross-site' -d "$LOGIN_BODY" "$BASE/_login")
eq "ac04_fetch_site_cross_400" "$code" "400"

# 跨站登出被拒绝
code=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: app.test' \
    -H 'Origin: https://attacker.invalid' -d '' "$BASE/_logout")
eq "ac04_cross_site_logout_400" "$code" "400"

# auth_cookie_csrf off 恢复旧行为
code=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: app.test' \
    -H 'Origin: https://attacker.invalid' -d "$LOGIN_BODY" "$BASE_NOCSRF/_login")
eq "ac04_csrf_off_login_302" "$code" "302"

# ---------- AC-07: 编码路径登录后回跳保持原始编码 ----------
python3 - "$PORT" "$TEST_DIR" <<'PY'
import http.client
import sys
import urllib.parse

port = int(sys.argv[1])

conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
conn.request("GET", "/report%23draft", headers={"Host": "app.test"})
r = conn.getresponse()
r.read()
loc = r.getheader("Location")
conn.close()

next_value = urllib.parse.parse_qs(
    urllib.parse.urlsplit(loc).query)["next"][0]

body = urllib.parse.urlencode(
    {"username": "user1", "password": "pass123", "next": next_value})
conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
conn.request("POST", "/_login", body,
             {"Host": "app.test",
              "Content-Type": "application/x-www-form-urlencoded"})
r = conn.getresponse()
r.read()
final = r.getheader("Location")
conn.close()

open(sys.argv[2] + "/ac07.out", "w").write(final or "")
PY

eq "ac07_encoded_path_preserved" "$(cat "$TEST_DIR/ac07.out")" "/report%23draft"

# 从真实登录页提取 hidden next，验证表单提交后的编码语义。
python3 - "$PORT" <<'PY'
import html, http.client, re, sys, urllib.parse
conn = http.client.HTTPConnection("127.0.0.1", int(sys.argv[1]), timeout=5)
for target in ("/search?q=a+b", "/a%20b"):
    conn.request("GET", target, headers={"Host": "app.test"})
    response = conn.getresponse()
    response.read()
    login_uri = response.getheader("Location")
    conn.request("GET", login_uri, headers={"Host": "app.test"})
    response = conn.getresponse()
    page = response.read().decode()
    value = html.unescape(re.search(r'name="next" value="([^"]*)"', page)[1])
    body = urllib.parse.urlencode({"username": "user1", "password": "pass123", "next": value})
    conn.request("POST", "/_login", body, {"Host": "app.test", "Content-Type": "application/x-www-form-urlencoded"})
    response = conn.getresponse()
    response.read()
    assert response.status == 302 and response.getheader("Location") == target, target
conn.close()
PY
ok "ac07_plus_and_encoded_space_roundtrip"

# 登录 body 的清零应仅覆盖当前 body，保留同连接下一条请求。
python3 - "$PORT" <<'PY'
import re, socket, sys
body = b"username=user1&password=pass123"
request = (b"POST /_login HTTP/1.1\r\nHost: app.test\r\n"
           + f"Content-Length: {len(body)}\r\n\r\n".encode() + body
           + b"GET /_login HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n")
with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5) as sock:
    sock.sendall(request)
    data = b""
    while True:
        part = sock.recv(65536)
        if not part:
            break
        data += part
assert re.findall(rb"HTTP/1.1 (\d{3})", data) == [b"302", b"200"], data
PY
ok "login_body_clear_preserves_next_request"

for prefix in __Host- __Secure- __host- __secure-; do
    sed "s/auth_cookie_secure off;/auth_cookie_secure off; auth_cookie_name ${prefix}test;/" \
        "$TEST_DIR/nginx.conf" > "$TEST_DIR/prefix.conf"
    if "$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/prefix.conf" -t >/dev/null 2>&1; then
        bad "prefix_${prefix}_requires_secure" accepted rejected
    else
        ok "prefix_${prefix}_requires_secure"
    fi
done
hdr=$(curl -sS -D - -o /dev/null -d "$LOGIN_BODY" \
    "http://127.0.0.1:$((PORT + 3))/_login")
printf '%s' "$hdr" | grep -q 'Set-Cookie: __Host-auth_cookie=.*; Secure' \
    && ok "host_prefix_secure_cookie" || bad "host_prefix_secure_cookie" missing secure

echo "---- summary PASS=$PASS FAIL=$FAIL ----"
[ "$FAIL" -eq 0 ]
