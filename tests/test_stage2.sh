#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 /path/to/nginx" >&2
    exit 2
fi

NGX_BIN=$(realpath "$1")
PORT=${PORT:-18093}
TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/auth-cookie-stage2.XXXXXX")
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
printf '%s\n' 'public' > "$TEST_DIR/www/public.html"
printf 'user1:%s\n' "$(openssl passwd -apr1 -salt testsalt pass123)" \
    > "$TEST_DIR/htpasswd"

cat > "$TEST_DIR/nginx.conf" <<EOF
worker_processes 1;
error_log $TEST_DIR/error.log notice;
pid $TEST_DIR/nginx.pid;
daemon on;

events { worker_connections 64; }

http {
    log_format audit '\$request_uri user=\$auth_cookie_user';
    access_log $TEST_DIR/access.log audit;
    client_body_temp_path $TEST_DIR/client_body_temp;
    proxy_temp_path $TEST_DIR/proxy_temp;
    fastcgi_temp_path $TEST_DIR/fastcgi_temp;
    uwsgi_temp_path $TEST_DIR/uwsgi_temp;
    scgi_temp_path $TEST_DIR/scgi_temp;

    server {
        listen 127.0.0.1:$PORT;
        listen 127.0.0.1:$((PORT + 1));
        http2 on;
        server_name localhost;

        auth_cookie_user_file $TEST_DIR/htpasswd;
        auth_cookie_secret $TEST_DIR/secret;
        auth_cookie_secure off;
        auth_cookie_login_rate off;
        auth_cookie_logout_uri /_logout;

        location / {
            root $TEST_DIR/www;
            index index.html;
            error_page 404 /public.html;
        }
        location = /public.html { root $TEST_DIR/www; auth_cookie_user_file off; }
        location /unauth/ {
            auth_cookie_user_file off;
            root $TEST_DIR/www;
            error_page 404 /public.html;
        }
    }
}
EOF

"$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf" -t
"$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf"
sleep 0.3

BASE="http://127.0.0.1:$PORT"

# 问题 8: 登录页安全响应头
hdr=$(curl -sS -D - -o /dev/null -H 'Host: localhost' "$BASE/_login")
printf '%s' "$hdr" | grep -qi 'content-type: text/html; charset=utf-8' \
    && ok "login_charset" || bad "login_charset" "$hdr" "charset=utf-8"
printf '%s' "$hdr" | grep -qi 'x-frame-options: DENY' \
    && ok "login_xfo" || bad "login_xfo" "$hdr" "DENY"
printf '%s' "$hdr" | grep -qi 'x-content-type-options: nosniff' \
    && ok "login_nosniff" || bad "login_nosniff" "$hdr" "nosniff"
printf '%s' "$hdr" | grep -qi 'cache-control: no-store' \
    && ok "login_nocache" || bad "login_nocache" "$hdr" "no-store"

# 问题 6: 未知用户不写带用户名的 INFO
code=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: localhost' \
    -d 'username=nouser&password=pass123&next=%2F' "$BASE/_login")
eq "unknown_user_status" "$code" "200"
if grep -q 'user "nouser" not found' "$TEST_DIR/error.log"; then
    bad "unknown_user_no_info" "logged" "silent"
else
    ok "unknown_user_no_info"
fi

# 问题 7: 错误密码仍拒绝,正确密码仍成功
code=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: localhost' \
    -d 'username=user1&password=wrong&next=%2F' "$BASE/_login")
eq "bad_password" "$code" "200"
jar="$TEST_DIR/cookies"
code=$(curl -sS -o /dev/null -c "$jar" -w '%{http_code}' -H 'Host: localhost' \
    -d 'username=user1&password=pass123&next=%2F' "$BASE/_login")
eq "good_login" "$code" "302"
code=$(curl -sS -o /dev/null -b "$jar" -w '%{http_code}' -H 'Host: localhost' \
    "$BASE/")
eq "authed_access" "$code" "200"

# 问题 3: 无 Host 登录回登录页,不 500,不签发 cookie
python3 - "$PORT" "$TEST_DIR/nohost.hdr" <<'PY'
import socket, sys
port = int(sys.argv[1])
body = b"username=user1&password=pass123&next=%2F"
req = (
    "POST /_login HTTP/1.0\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: %d\r\n"
    "\r\n"
) % len(body)
s = socket.create_connection(("127.0.0.1", port), 3)
s.sendall(req.encode() + body)
data = b""
while True:
    c = s.recv(4096)
    if not c:
        break
    data += c
s.close()
open(sys.argv[2], "wb").write(data)
print(data.split(b" ", 2)[1].decode() if data.startswith(b"HTTP") else "000")
text = data.decode("latin1", "replace")
print("SETCOOKIE" if "set-cookie:" in text.lower() else "NOCOOKIE")
print("HASERROR" if "缺少 Host" in text else "NOERROR")
PY
nohost=$(python3 -c 'import sys; print(open(sys.argv[1],"rb").read().split(b" ",2)[1].decode())' "$TEST_DIR/nohost.hdr")
eq "nohost_login_not_500" "$( [ "$nohost" != 500 ] && echo ok || echo 500 )" "ok"
eq "nohost_login_status" "$nohost" "200"
text=$(python3 -c 'import sys; print(open(sys.argv[1],"rb").read().decode("latin1","replace").lower())' "$TEST_DIR/nohost.hdr")
case "$text" in
    *set-cookie:*) bad "nohost_no_cookie" "set-cookie" "none" ;;
    *) ok "nohost_no_cookie" ;;
esac

# 长度未知的登录在读 body 前返回 411。
python3 - "$PORT" <<'PY'
import socket, sys
port = int(sys.argv[1])
body = b"username=user1&password=pass123&next=%2F"
req = (
    "POST /_login HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: close\r\n"
    "\r\n"
    "%x\r\n" % len(body)
).encode() + body + b"\r\n0\r\n\r\n"
s = socket.create_connection(("127.0.0.1", port), 3)
s.sendall(req)
data = b""
while True:
    c = s.recv(4096)
    if not c:
        break
    data += c
s.close()
print(data.split(b" ", 2)[1].decode() if data.startswith(b"HTTP") else "000")
PY
chunked=$(python3 - "$PORT" <<'PY'
import socket, sys
port = int(sys.argv[1])
body = b"username=user1&password=pass123&next=%2F"
req = (
    "POST /_login HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: close\r\n"
    "\r\n"
    "%x\r\n" % len(body)
).encode() + body + b"\r\n0\r\n\r\n"
s = socket.create_connection(("127.0.0.1", port), 3)
s.sendall(req)
data = b""
while True:
    c = s.recv(4096)
    if not c:
        break
    data += c
s.close()
print(data.split(b" ", 2)[1].decode() if data.startswith(b"HTTP") else "000")
PY
)
eq "chunked_login_411" "$chunked" "411"

# Content-Length 超大仍 413; 正常小表单仍 302
code=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: localhost' \
    -d "username=user1&password=pass123&pad=$(python3 -c 'print("A"*9000)')" \
    "$BASE/_login")
eq "oversize_content_length" "$code" "413"

eq "empty_logout_http1" "$(curl -sS -o /dev/null -w '%{http_code}' \
    -X POST "$BASE/_logout")" "302"
eq "empty_login_http1" "$(curl -sS -o /dev/null -w '%{http_code}' \
    -X POST "$BASE/_login")" "400"
eq "empty_logout_http2" "$(curl -sS --http2-prior-knowledge -o /dev/null \
    -w '%{http_code}' -X POST "http://127.0.0.1:$((PORT + 1))/_logout")" "302"
eq "unknown_length_http2" "$(curl -sS --http2-prior-knowledge -o /dev/null \
    -w '%{http_code}' -H 'Content-Length:' -d 'username=user1&password=pass123' \
    "http://127.0.0.1:$((PORT + 1))/_login")" "411"

curl -sS -o /dev/null -b "$jar" -H 'Host: localhost' "$BASE/missing-auth"
curl -sS -o /dev/null -H 'Host: localhost' "$BASE/unauth/missing"
grep -q '^/missing-auth user=user1$' "$TEST_DIR/access.log" \
    && ok "redirect_user_retained" || bad "redirect_user_retained" missing user1
grep -q '^/unauth/missing user=-$' "$TEST_DIR/access.log" \
    && ok "redirect_unauth_user_empty" || bad "redirect_unauth_user_empty" found empty

echo "---- summary PASS=$PASS FAIL=$FAIL ----"
[ "$FAIL" -eq 0 ]
