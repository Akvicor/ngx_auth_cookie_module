/*
 * 单元测试桩:ngx_config.h 的最小替代,只提供标准库依赖。
 * 用于脱离 nginx 编译正式的 crypto.c / util.c。
 */

#ifndef TEST_NGX_CONFIG_H
#define TEST_NGX_CONFIG_H

#define _GNU_SOURCE

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#endif
