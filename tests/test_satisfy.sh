#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 /path/to/nginx" >&2
    exit 2
fi

NGX_BIN=$(realpath "$1")
PORT=${PORT:-18091}
TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/auth-cookie-satisfy.XXXXXX")
unset NGINX

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

mkdir -p "$TEST_DIR/www" "$TEST_DIR/logs" "$TEST_DIR/client_body_temp"
chmod 755 "$TEST_DIR" "$TEST_DIR/www" "$TEST_DIR/logs"
printf '%s\n' 'protected' > "$TEST_DIR/www/index.html"
printf 'user1:%s\n' "$(openssl passwd -apr1 -salt testsalt pass123)" \
    > "$TEST_DIR/htpasswd"

cat > "$TEST_DIR/nginx.conf" <<EOF
worker_processes 1;
error_log $TEST_DIR/error.log notice;
pid $TEST_DIR/nginx.pid;
daemon on;

events { worker_connections 64; }

http {
    access_log $TEST_DIR/access.log;
    client_body_temp_path $TEST_DIR/client_body_temp;
    proxy_temp_path $TEST_DIR/proxy_temp;
    fastcgi_temp_path $TEST_DIR/fastcgi_temp;
    uwsgi_temp_path $TEST_DIR/uwsgi_temp;
    scgi_temp_path $TEST_DIR/scgi_temp;

    server {
        listen 127.0.0.1:$PORT;
        server_name localhost;

        auth_cookie_user_file $TEST_DIR/htpasswd;
        auth_cookie_secret $TEST_DIR/secret;
        auth_cookie_secure off;
        auth_cookie_login_rate off;
        satisfy any;
        allow 127.0.0.1;
        deny all;

        location / {
            root $TEST_DIR/www;
            index index.html;
        }
    }
}
EOF

"$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf" -t
"$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf"
sleep 0.3

BASE="http://127.0.0.1:$PORT"
code=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: localhost' "$BASE/")
if [ "$code" != 302 ]; then
    echo "FAIL satisfy_any_unauth got=$code expect=302" >&2
    exit 1
fi

jar="$TEST_DIR/cookies"
code=$(curl -sS -o /dev/null -c "$jar" -w '%{http_code}' -H 'Host: localhost' \
    -d 'username=user1&password=pass123&next=%2F' "$BASE/_login")
if [ "$code" != 302 ]; then
    echo "FAIL satisfy_any_login got=$code expect=302" >&2
    exit 1
fi

code=$(curl -sS -o "$TEST_DIR/body.txt" -b "$jar" -w '%{http_code}' \
    -H 'Host: localhost' "$BASE/")
body=$(cat "$TEST_DIR/body.txt")
if [ "$code" != 200 ] || [ "$body" != protected ]; then
    echo "FAIL satisfy_any_authed got=$code body=$body" >&2
    exit 1
fi

echo "auth_cookie satisfy any passed"
