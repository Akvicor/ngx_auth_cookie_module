#!/bin/sh
# 单元测试:用 stub/ 桩编译正式的 crypto.c 与 util.c,覆盖 HMAC 向量、
# 签发/验签、篡改/过期/绑定关系、sanitize_next 与 load_secret。
set -eu

TEST_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULE_DIR="$TEST_DIR/.."
BIN=$(mktemp "${TMPDIR:-/tmp}/auth-cookie-unit.XXXXXX")
trap 'rm -f "$BIN"' EXIT HUP INT TERM

${CC:-cc} -std=c99 -Wall -Wextra -Werror \
    -I"$TEST_DIR/stub" \
    -I"$MODULE_DIR" \
    "$MODULE_DIR/ngx_http_auth_cookie_crypto.c" \
    "$MODULE_DIR/ngx_http_auth_cookie_util.c" \
    "$TEST_DIR/test_crypto.c" \
    -lssl -lcrypto \
    -o "$BIN"

"$BIN"
