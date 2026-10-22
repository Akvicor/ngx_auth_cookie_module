SHELL := /bin/sh

NGINX_BIN ?=

.PHONY: verify test

# 单元测试直接编译模块实现，同时检查全部回归脚本语法。
verify:
	@for script in tests/*.sh; do sh -n "$$script" || exit; done
	./tests/run-hmac.sh

# 集成测试使用已静态编入本模块的 nginx，各组用例顺序运行。
test:
	@test -n "$(NGINX_BIN)" && test -x "$(NGINX_BIN)" || { printf '%s\n' 'Set NGINX_BIN to an executable nginx binary with this module' >&2; exit 1; }
	PORT=18120 ./tests/integration.sh "$(NGINX_BIN)"
	PORT=18121 ./tests/test_users.sh "$(NGINX_BIN)"
	PORT=18122 ./tests/test_page.sh "$(NGINX_BIN)"
	PORT=18123 ./tests/test_satisfy.sh "$(NGINX_BIN)"
	PORT=18124 ./tests/test_stage2.sh "$(NGINX_BIN)"
	PORT=18125 ./tests/test_security.sh "$(NGINX_BIN)"
	PORT=18126 ./tests/test_rate_limit.sh "$(NGINX_BIN)"
	PORT=18140 ./tests/test_basic.sh "$(NGINX_BIN)"
