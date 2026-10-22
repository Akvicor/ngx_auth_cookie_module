#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 /path/to/nginx" >&2
    exit 2
fi

NGX_BIN=$(realpath "$1")
PORT=${PORT:-18099}
TEST_DIR=$(mktemp -d "${TMPDIR:-/tmp}/auth-cookie-users.XXXXXX")
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
printf 'user1:%s\nuser2:%s\n' \
    "$(openssl passwd -apr1 -salt testsalt pass123)" \
    "$(openssl passwd -apr1 -salt testsalt otherpass)" \
    > "$TEST_DIR/htpasswd"

printf 'user1:%s\n' "$(openssl passwd -apr1 -salt other separate)" > "$TEST_DIR/other"
printf 'Alice:%s\nalice:%s\nAlice:%s\n' \
    "$(openssl passwd -apr1 -salt first firstpass)" \
    "$(openssl passwd -apr1 -salt lower lowerpass)" \
    "$(openssl passwd -apr1 -salt second secondpass)" > "$TEST_DIR/indexed"
for loc in shared1 shared2 other indexed; do
    mkdir -p "$TEST_DIR/www/$loc"
    printf '%s\n' protected > "$TEST_DIR/www/$loc/index.html"
done

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

        location / {
            root $TEST_DIR/www;
            index index.html;
        }
        location /shared1/ { root $TEST_DIR/www; error_page 404 /other/index.html; }
        location /shared2/ { root $TEST_DIR/www; }
        location /other/ {
            root $TEST_DIR/www;
            auth_cookie_user_file $TEST_DIR/other;
            auth_cookie_login_uri /other/_login;
        }
        location /indexed/ {
            root $TEST_DIR/www;
            auth_cookie_user_file $TEST_DIR/indexed;
            auth_cookie_login_uri /indexed/_login;
        }
    }
}
EOF

"$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf" -t
"$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf"
sleep 0.3
BASE="http://127.0.0.1:$PORT"

# 登录两个用户
hdr=$(curl -sS -D - -o /dev/null -H 'Host: localhost' \
    -d 'username=user1&password=pass123&next=%2F' "$BASE/_login")
ck1=$(printf '%s\n' "$hdr" | awk 'tolower($1)=="set-cookie:" {print $2}' | tr -d '\r' | cut -d';' -f1)
hdr=$(curl -sS -D - -o /dev/null -H 'Host: localhost' \
    -d 'username=user2&password=otherpass&next=%2F' "$BASE/_login")
ck2=$(printf '%s\n' "$hdr" | awk 'tolower($1)=="set-cookie:" {print $2}' | tr -d '\r' | cut -d';' -f1)
eq "user1_cookie" "$(printf '%s' "$ck1" | grep -c auth_cookie || true)" "1"
eq "user2_cookie" "$(printf '%s' "$ck2" | grep -c auth_cookie || true)" "1"

code=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: localhost' -H "Cookie: $ck1" "$BASE/")
eq "user1_before_reload" "$code" "200"
code=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: localhost' -H "Cookie: $ck2" "$BASE/")
eq "user2_before_reload" "$code" "200"

# 同路径共享快照，不同路径保持独立认证域，用户名区分大小写且重名首条生效。
for loc in shared1 shared2; do
    eq "${loc}_inherited_cookie" "$(curl -sS -o /dev/null -w '%{http_code}' \
        -H 'Host: localhost' -H "Cookie: $ck1" "$BASE/$loc/index.html")" "200"
done
eq "different_file_cookie_rejected" "$(curl -sS -o /dev/null -w '%{http_code}' \
    -H 'Host: localhost' -H "Cookie: $ck1" "$BASE/other/index.html")" "302"
eq "redirect_other_file_reverified" "$(curl -sS -o /dev/null -w '%{http_code}' \
    -H 'Host: localhost' -H "Cookie: $ck1" "$BASE/shared1/missing")" "302"
eq "different_file_password" "$(curl -sS -o /dev/null -w '%{http_code}' \
    -H 'Host: localhost' -d 'username=user1&password=separate' "$BASE/other/_login")" "302"
eq "duplicate_first_password" "$(curl -sS -o /dev/null -w '%{http_code}' \
    -d 'username=Alice&password=firstpass' "$BASE/indexed/_login")" "302"
eq "duplicate_later_password_rejected" "$(curl -sS -o /dev/null -w '%{http_code}' \
    -d 'username=Alice&password=secondpass' "$BASE/indexed/_login")" "200"
eq "case_sensitive_user" "$(curl -sS -o /dev/null -w '%{http_code}' \
    -d 'username=alice&password=lowerpass' "$BASE/indexed/_login")" "302"

# 改文件但未 reload: 旧会话仍有效,新密码尚未生效
printf 'user1:%s\nuser2:%s\n' \
    "$(openssl passwd -apr1 -salt newsalt newpass)" \
    "$(openssl passwd -apr1 -salt testsalt otherpass)" \
    > "$TEST_DIR/htpasswd"
code=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: localhost' -H "Cookie: $ck1" "$BASE/")
eq "user1_still_valid_before_reload" "$code" "200"
code=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: localhost' \
    -d 'username=user1&password=newpass&next=%2F' "$BASE/_login")
eq "new_password_not_live_before_reload" "$code" "200"

# reload 后: user1 旧 cookie 失效,user2 仍有效,新密码可登录
"$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf" -s reload
sleep 0.4
code=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: localhost' -H "Cookie: $ck1" "$BASE/")
eq "user1_revoked_after_reload" "$code" "302"
code=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: localhost' -H "Cookie: $ck2" "$BASE/")
eq "user2_kept_after_reload" "$code" "200"
hdr=$(curl -sS -D - -o /dev/null -H 'Host: localhost' \
    -d 'username=user1&password=newpass&next=%2F' "$BASE/_login")
ck1b=$(printf '%s\n' "$hdr" | awk 'tolower($1)=="set-cookie:" {print $2}' | tr -d '\r' | cut -d';' -f1)
code=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: localhost' -H "Cookie: $ck1b" "$BASE/")
eq "user1_new_password_after_reload" "$code" "200"

# 删除 user2 后 reload,旧 cookie 失效
printf 'user1:%s\n' \
    "$(openssl passwd -apr1 -salt newsalt newpass)" \
    > "$TEST_DIR/htpasswd"
"$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf" -s reload
sleep 0.4
code=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: localhost' -H "Cookie: $ck2" "$BASE/")
eq "deleted_user_revoked" "$code" "302"
code=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: localhost' -H "Cookie: $ck1b" "$BASE/")
eq "remaining_user_kept" "$code" "200"

# 符号链接使用真实目标文件；reload 后可正常登录。
ln -s "$TEST_DIR/htpasswd" "$TEST_DIR/htpasswd.link"
sed "s|$TEST_DIR/htpasswd|$TEST_DIR/htpasswd.link|" "$TEST_DIR/nginx.conf" \
    > "$TEST_DIR/nginx.link.conf"
if "$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.link.conf" -t >/dev/null 2>&1; then
    ok "symlink_htpasswd_accepted"
else
    bad "symlink_htpasswd_accepted" "fail" "ok"
fi
cp "$TEST_DIR/nginx.link.conf" "$TEST_DIR/nginx.conf"
"$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/nginx.conf" -s reload
sleep 0.4
eq "symlink_htpasswd_login" "$(curl -sS -o /dev/null -w '%{http_code}' \
    -H 'Host: localhost' -d 'username=user1&password=newpass' "$BASE/_login")" "302"

ln -s "$TEST_DIR/secret" "$TEST_DIR/secret.link"
sed "s|auth_cookie_secret $TEST_DIR/secret;|auth_cookie_secret $TEST_DIR/secret.link;|" \
    "$TEST_DIR/nginx.conf" > "$TEST_DIR/secret.conf"
"$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/secret.conf" -t >/dev/null 2>&1 \
    && ok "symlink_secret_accepted" || bad "symlink_secret_accepted" fail ok
chmod 644 "$TEST_DIR/secret"
if "$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/secret.conf" -t >/dev/null 2>&1; then
    bad "symlink_secret_permissions" accepted rejected
else
    ok "symlink_secret_permissions"
fi
chmod 600 "$TEST_DIR/secret"
if [ "$(id -u)" = 0 ]; then
    chown 65534 "$TEST_DIR/secret"
    if "$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/secret.conf" -t >/dev/null 2>&1; then
        bad "symlink_secret_owner" accepted rejected
    else
        ok "symlink_secret_owner"
    fi
    chown 0 "$TEST_DIR/secret"
fi

# 高 cost 告警按文件快照只输出一次，包括继承的两个 location。
for cost in 10 11; do
    printf 'user1:$2y$%s$abcdefghijklmnopqrstuu0123456789012345678901234567890\n' \
        "$cost" > "$TEST_DIR/warning-users"
    sed "s|auth_cookie_user_file $TEST_DIR/htpasswd.link;|auth_cookie_user_file $TEST_DIR/warning-users;|" \
        "$TEST_DIR/nginx.conf" > "$TEST_DIR/warning.conf"
    "$NGX_BIN" -p "$TEST_DIR/" -c "$TEST_DIR/warning.conf" -t > "$TEST_DIR/warning.out" 2>&1
    count=$(grep -c 'bcrypt cost .* exceeds 10' "$TEST_DIR/warning.out" || true)
    if [ "$cost" = 11 ]; then expected=1; else expected=0; fi
    eq "bcrypt_cost_${cost}_warning_once" "$count" "$expected"
done

echo "---- summary PASS=$PASS FAIL=$FAIL ----"
[ "$FAIL" -eq 0 ]
