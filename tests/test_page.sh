#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 /path/to/nginx" >&2
    exit 2
fi

NGX_BIN=$(realpath "$1")
PORT=${PORT:-18102}
TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/auth-cookie-page.XXXXXX")
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

mkdir -p "$TEST_DIR/www" "$TEST_DIR/logs" "$TEST_DIR/client_body_temp"
chmod 755 "$TEST_DIR" "$TEST_DIR/www" "$TEST_DIR/logs"
printf '%s\n' 'protected' > "$TEST_DIR/www/index.html"
printf 'user1:%s\n' "$(openssl passwd -apr1 -salt testsalt pass123)" \
    > "$TEST_DIR/htpasswd"
cat > "$TEST_DIR/login.html" <<'EOF'
<html><title>{{title}}</title><form action="{{action}}">
<input name="next" value="{{next}}"><div>{{error}}</div>OLD</form></html>
EOF

write_conf() {
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
        auth_cookie_page $TEST_DIR/login.html;
        location / { root $TEST_DIR/www; index index.html; }
    }
}
EOF
}

write_conf
"$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf" -t
"$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf"
sleep 0.3
BASE="http://127.0.0.1:$PORT"

page=$(curl -sS -H 'Host: localhost' "$BASE/_login")
case "$page" in
    *OLD*) ok "custom_page_loaded" ;;
    *) bad "custom_page_loaded" "$page" "OLD" ;;
esac

# 改文件未 reload: 仍是旧内容
sed 's/OLD/NEW/' "$TEST_DIR/login.html" > "$TEST_DIR/login.html.new"
mv "$TEST_DIR/login.html.new" "$TEST_DIR/login.html"
page=$(curl -sS -H 'Host: localhost' "$BASE/_login")
case "$page" in
    *OLD*) ok "page_unchanged_before_reload" ;;
    *) bad "page_unchanged_before_reload" "$page" "OLD" ;;
esac

"$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf" -s reload
sleep 0.4
page=$(curl -sS -H 'Host: localhost' "$BASE/_login")
case "$page" in
    *NEW*) ok "page_updated_after_reload" ;;
    *) bad "page_updated_after_reload" "$page" "NEW" ;;
esac

# 符号链接页面配置通过并在 reload 后渲染正确。
ln -s "$TEST_DIR/login.html" "$TEST_DIR/login.link.html"
sed "s|$TEST_DIR/login.html|$TEST_DIR/login.link.html|" "$TEST_DIR/nginx.conf" \
    > "$TEST_DIR/nginx.link.conf"
if "$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.link.conf" -t >/dev/null 2>&1; then
    ok "symlink_page_accepted"
else
    bad "symlink_page_accepted" "fail" "ok"
fi
cp "$TEST_DIR/nginx.link.conf" "$TEST_DIR/nginx.conf"
"$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf" -s reload
sleep 0.4
page=$(curl -sS -H 'Host: localhost' "$BASE/_login")
case "$page" in
    *NEW*) ok "symlink_page_rendered" ;;
    *) bad "symlink_page_rendered" "$page" "NEW" ;;
esac

# 70KB 页面应可加载
python3 - "$TEST_DIR/login70.html" <<'PY'
import sys
open(sys.argv[1], "w").write("<html>{{title}}" + ("X" * 70000) + "{{error}}</html>")
PY
sed "s|$TEST_DIR/login.link.html|$TEST_DIR/login70.html|" "$TEST_DIR/nginx.conf" \
    > "$TEST_DIR/nginx.70.conf"
if "$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.70.conf" -t >/dev/null 2>&1; then
    ok "page_70kb_accepted"
else
    bad "page_70kb_accepted" "fail" "ok"
fi

echo "---- summary PASS=$PASS FAIL=$FAIL ----"
[ "$FAIL" -eq 0 ]
