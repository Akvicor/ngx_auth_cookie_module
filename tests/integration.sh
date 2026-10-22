#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 /path/to/nginx" >&2
    exit 2
fi

NGINX=$(realpath "$1")
PORT=${PORT:-18080}
TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/auth-cookie-integration.XXXXXX")

cleanup() {
    if [ -f "$TEST_DIR/nginx.pid" ]; then
        "$NGINX" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf" -s quit \
            >/dev/null 2>&1 || true
    fi
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$TEST_DIR/www" "$TEST_DIR/logs"
chmod 755 "$TEST_DIR" "$TEST_DIR/www" "$TEST_DIR/logs"
printf '%s\n' 'protected' > "$TEST_DIR/www/index.html"
printf 'user1:%s\n' "$(openssl passwd -apr1 -salt testsalt pass123)" \
    > "$TEST_DIR/htpasswd"

cat > "$TEST_DIR/nginx.conf" <<EOF
worker_processes 2;
error_log $TEST_DIR/error.log notice;
pid $TEST_DIR/nginx.pid;

events { worker_connections 128; }

http {
    access_log $TEST_DIR/access.log;
    client_body_temp_path $TEST_DIR/body;
    proxy_temp_path $TEST_DIR/proxy;
    fastcgi_temp_path $TEST_DIR/fastcgi;
    uwsgi_temp_path $TEST_DIR/uwsgi;
    scgi_temp_path $TEST_DIR/scgi;

    server {
        listen 127.0.0.1:$PORT;
        server_name localhost;

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
}
EOF

"$NGINX" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf" -t
"$NGINX" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf"

BASE_URL="http://127.0.0.1:$PORT"
COOKIE_JAR="$TEST_DIR/cookies"

[ "$(curl -sS -o /dev/null -w '%{http_code}' "$BASE_URL/")" = 302 ]
[ "$(curl -sS -o /dev/null -w '%{http_code}' "$BASE_URL/_login")" = 200 ]
[ "$(curl -sS -o /dev/null -w '%{http_code}' -c "$COOKIE_JAR" \
    -d 'username=user1&password=pass123&next=%2F' \
    "$BASE_URL/_login")" = 302 ]
[ "$(curl -sS -o /dev/null -w '%{http_code}' -b "$COOKIE_JAR" \
    "$BASE_URL/")" = 200 ]
[ "$(curl -sS -o /dev/null -w '%{http_code}' -b "$COOKIE_JAR" \
    -d '' "$BASE_URL/_logout")" = 302 ]
# GNU/BSD stat 使用各自的八进制权限格式，保持同一权限断言。
case "$(uname -s)" in
    Darwin) permission=$(stat -f '%Lp' "$TEST_DIR/secret") ;;
    *) permission=$(stat -c '%a' "$TEST_DIR/secret") ;;
esac
[ "$permission" = 600 ]

echo "auth_cookie integration passed"
