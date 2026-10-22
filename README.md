# ngx_http_auth_cookie_module

[README-EN](README-en_US.md)

[博客链接](https://www.ksyaki.com/archives/nginx-cookiedeng-lu-ren-zheng-cha-jian)

`ngx_http_auth_cookie_module` 为 nginx 提供基于 HMAC 签名 Cookie 的会话认证，
以及共用用户文件和登录限流的 HTTP Basic 客户端认证。

## 构建

模块依赖 nginx `ngx_crypt()`、libcrypt 与 OpenSSL。配置 nginx 时加入：

```sh
./configure \
  --with-http_ssl_module \
  --add-module=../ngx_auth_cookie_module
```

## 配置

```nginx
server {
    listen 443 ssl;
    server_name app.example.com;

    auth_cookie_user_file /etc/nginx/htpasswd;
    auth_cookie_page basic;

    # auth_cookie_name auth_cookie;
    # auth_cookie_secure on;
    # auth_cookie_secret /etc/nginx/auth_cookie.secret;
    # auth_cookie_session_ttl 12h;
    # auth_cookie_title "Restricted Content";
    # auth_cookie_login_uri /_login;
    # auth_cookie_logout_uri /_logout;
    # auth_cookie_csrf on;
    # auth_cookie_basic on;
    # auth_cookie_login_rate 10 1000ms 1 1000ms;
    # auth_cookie_login_rate_key ip_username;
    # auth_cookie_login_rate_refund on;
    # auth_cookie_login_rate_trusted_proxy 203.0.113.0/24;
    # auth_cookie_login_rate_ip_header X-Forwarded-For;

    location / {
        proxy_pass http://127.0.0.1:3080;
    }
}
```

| 指令 | 默认值 | 说明 |
| --- | --- | --- |
| `auth_cookie_user_file <path\|off>` | `off` | htpasswd 用户文件；设置路径即启用认证，子 location 可用 `off` 关闭继承的认证 |
| `auth_cookie_page <basic\|premium\|绝对路径>` | `basic` | 登录页模板 |
| `auth_cookie_name <name>` | `auth_cookie` | Cookie 名称 |
| `auth_cookie_secure <on\|off>` | `on` | 设置 Cookie 的 `Secure` 属性 |
| `auth_cookie_secret <path>` | `/etc/nginx/auth_cookie.secret` | HMAC 密钥文件 |
| `auth_cookie_session_ttl <time>` | `12h` | 会话有效期，必须大于零 |
| `auth_cookie_title <text>` | `登录` | 登录页标题 |
| `auth_cookie_login_uri <uri>` | `/_login` | 登录 URI |
| `auth_cookie_logout_uri <uri>` | 未设置 | POST 登出 URI |
| `auth_cookie_csrf <on\|off>` | `on` | 网页登录、Basic 认证与登出共用的同源校验 |
| `auth_cookie_basic <on\|off>` | `on` | 接受客户端主动发送的 HTTP Basic 凭据 |
| `auth_cookie_login_rate <IP容量> <IP周期> <IP+用户名容量> <IP+用户名周期> \| off` | `10 1000ms 1 1000ms` | 网页登录 POST 与 Basic 认证共用的 IP 桶和 IP+用户名桶参数；`off` 关闭全部限流 |
| `auth_cookie_login_rate_key <ip\|username\|ip_username>` | `ip_username` | 登录限流统计键；`ip_username` 先检查 IP 桶再检查 IP+用户名桶 |
| `auth_cookie_login_rate_refund <on\|off>` | `on` | 网页登录和 Basic 认证成功后退回预扣令牌；`off` 时成功也计数 |
| `auth_cookie_login_rate_zone_size <size>` | `1m` | 每个登录限流共享内存区的容量，只能在 `http` 层级配置 |
| `auth_cookie_login_rate_trusted_proxy <IP或CIDR或unix:...>` | 空 | 可信代理，可多行或多值配置 |
| `auth_cookie_login_rate_ip_header <header...>` | 未设置 | 显式 IP Header 顺序，可多行或多值配置 |

`auth_cookie_secret` 在配置加载阶段读取。文件不存在时会生成 256 位随机密钥并以 `0600` 写入，因此 `nginx -t` 也可能创建该文件。已有文件须为普通文件、至少 32 字节，且不能向 group/other 授权。

htpasswd、secret 与自定义登录页支持符号链接，可用于 Kubernetes Secret/ConfigMap
挂载。secret 的属主、权限与大小校验针对链接目标；secret 所在目录及链接路径上的目录
应仅允许 nginx master 用户写入（以 root 启动时为 root）。挂载目标也须满足 secret 的
权限要求。

### Location 级配置

登录 URI 需要落入同一个 location 配置。前缀 location 可按下面的方式设置：

```nginx
location /private/ {
    auth_cookie_user_file /etc/nginx/private.htpasswd;
    auth_cookie_login_uri /private/_login;
    proxy_pass http://127.0.0.1:3080;
}
```

server 级配置可直接使用默认 `/_login`。

### HTTP Basic 兼容认证

设置 `auth_cookie_user_file` 后，同一用户文件同时用于网页登录和客户端主动发送的
HTTP Basic 认证。`auth_cookie_basic off` 时 Basic 请求头不参与认证和登录限流，
请求按未认证处理并跳转网页登录。旧服务可直接发送 `Authorization: Basic ...`，例如：

```sh
curl -u '用户名:密码' https://app.example.com/private/
```

有效 Cookie 优先；没有有效 Cookie 时，Basic 凭据通过后直接访问资源，并设置
`$auth_cookie_user`，会话 Cookie 由网页登录流程签发。Basic 用户文件同样支持 APR1
和 bcrypt，修改后在 reload 或重启时生效。内部重定向按目标 location 的用户表重新校验。
原始 Authorization 请求头保留，供反向代理和其他认证模块使用。

两种认证入口共用用户名、密码校验和 `auth_cookie_csrf` 同源规则。用户名最长
128 字节，并拒绝 NUL、冒号、回车和换行；密码非空且拒绝 NUL。表单字段的 4096 字节
上限在 URL 解码前检查，Basic 密码在 Base64 解码后按同一上限检查。
认证凭据来自 Basic 请求头，业务请求体继续遵循应用自身的上传配置；登录/登出
接口保持原有的表单体大小及长度要求。

未携带 Basic 凭据的请求继续跳转网页登录；Basic 格式错误、用户不存在或密码错误
返回 401，同源校验失败返回 400，超出登录限流返回 429，显式 IP Header 模式下来源
无效返回 400。模块不发送 `WWW-Authenticate` 挑战，因此浏览器继续使用网页登录页，
不会由本模块触发原生认证弹框。客户端应主动发送 Basic 头（如 `curl -u`），而非等待
401 挑战后再发送；仅使用本模块即可提供这条兼容路径。额外配置的原生 `auth_basic`
仍按其自身规则发送挑战。与 Cookie 路径一致，认证失败直接返回响应，
认证成功后其他访问控制按 `satisfy` 配置执行。

Basic 按请求校验密码，并与网页登录 POST 共用 `auth_cookie_login_rate` 限额，
计数规则见“登录限流”。默认认证成功的 Basic 请求不消耗额度，因此持有正确凭据的
客户端每次请求都会计算一次密码哈希；高频调用的账号建议使用 APR1 或较低的 bcrypt
cost，也可配置 `auth_cookie_login_rate_refund off` 让成功请求同样计数。
内部重定向时，相同桶键及限流参数只检查一次；目标认证域变化时按目标配置检查和校验。
已通过 Cookie 认证的资源访问沿用会话，不涉及登录额度。生产环境使用 HTTPS。

## 自定义页面

绝对路径页面在配置加载时读入，最大 128 KiB，渲染结果最大 512 KiB。文件修改在 `reload` 或重启后生效。模板支持以下占位符：

- `{{title}}`
- `{{error}}`
- `{{next}}`
- `{{action}}`

动态值会进行 HTML 转义。占位符应放在文本节点或带双引号的属性中。
登录表单须使用 POST，并提交 `username`、`password` 与可选的 `next` 字段。
替换值中的文本不会被再次当作占位符展开。

## 会话与安全边界

Cookie 格式为：

```text
base64url(user:exp:nonce).hex(OpenSSL HMAC-SHA256(secret, host + user_file + fingerprint + payload))
```

签名绑定请求 host 与用户文件，来自其他虚拟主机或认证域的 Cookie 无法重放。`next` 只接受站内绝对路径或 authority 与当前 Host 一致的 HTTP(S) URL，并拒绝控制字符、反斜杠和协议相对 URL。

`next` 输出保持原始 URI 编码，`+` 与 `%20` 可正常回跳。绝对 URL 的 authority 段含
百分号编码时拒绝。单个表单字段解码前上限为 4096 字节，回跳长度取决于 URL 的编码
膨胀：复杂查询串的原始 URL 约超过 2.7KB 时可能回退到 `/`（实测 2505B 可回跳，3005B
回退）；该阈值不是所有 URL 的统一长度上限。

会话无服务端状态，多 worker 可直接验签。htpasswd 在配置加载时读入内存，
文件修改在 `reload` 或重启后生效；同一用途、同一路径的文件在一次配置加载中只读取
一次，server/location 共享该快照，reload 时重新读取。
签发绑定当前用户密码哈希指纹，删除用户或改密并 reload 后旧会话失效。
登出会清除浏览器 Cookie。生产环境应使用 HTTPS。

HTTPS 站点推荐配置 `auth_cookie_name __Host-auth_cookie;`。浏览器要求 `__Host-`
Cookie 带 `Secure`、`Path=/` 且为 host-only，因此同一注册域的其他子域名无法注入或遮蔽
该 Cookie。`__Host-` 或 `__Secure-` 前缀（不区分大小写）须配合
`auth_cookie_secure on`，否则配置检查失败；默认 Cookie 名仍为 `auth_cookie`。

用户名不存在和密码错误返回相同页面、文案与状态码，但响应耗时不同。用户名按公开
标识使用，认证安全依赖登录限流与强密码。

登录后会清零模块的密码副本及原始内存请求体，清零是尽力而为：TLS、HTTP/2 等内部
缓冲区仍可能残留明文。登录 location 应使用内存请求体，保持 `client_body_in_file_only off`；
core dump 可能包含近期登录的明文密码，应限制生成与分发。Basic 认证时模块清零
用于哈希计算的密码副本；请求头解码出的用户名和密码与 `$remote_user` 及原生
`auth_basic` 共用，保留至请求结束。

登录/登出 POST 的请求体上限为 8KB（不含请求头，不影响受保护应用的上传）。有请求体时
须带 `Content-Length`，chunked 或 HTTP/2、HTTP/3 有请求体却无长度时返回 411；明确长度
超过 8KB 返回 413。无请求体可省略长度：登出正常 302，空登录与 `Content-Length: 0`
一致返回 400。该上限独立于应用的 `client_max_body_size`。

## 登录限流

模块对登录 URI 的 POST 和资源请求中的 Basic 认证限流，默认使用 `ip_username` 两级限流。
IP 桶默认为每个来源
10 次/1000ms，IP+用户名桶默认为每个 IP+用户名组合 1 次/1000ms。
每次网页登录 POST 和 Basic 认证在密码校验前预扣令牌，密码校验成功后退回
（`auth_cookie_login_rate_refund off` 时成功也保留扣费）；
密码错误、用户名不存在、表单或凭据格式错误、CSRF 失败均保留扣费。预扣使并发
尝试同样受额度约束；额度耗尽时，正确密码也返回 429，直到令牌恢复。
GET/HEAD 登录页、登出 POST 和已通过 Cookie 认证的资源访问不计入。
超限返回 HTTP 429，网页登录复用登录页显示错误，Basic 返回标准错误响应。
限流状态由全部 worker 共享，同一个 Nginx 实例内按认证配置隔离。

```nginx
auth_cookie_login_rate 10 1m 1 10s;    # 每个 IP 10 次/分钟，每个 IP+用户名 6 次/分钟
auth_cookie_login_rate_key ip_username;
```

`ip` 模式使用前两参数限制 IP；`username` 模式使用后两参数限制来源 IP + 用户名；
`ip_username` 模式先用前两参数检查 IP，再用后两参数检查来源 IP + 用户名。
CSRF 失败、空用户名或空密码，以及无法取得有效用户名的认证尝试回退到来源 IP。
令牌和恢复周期都使用整数计算，不使用浮点。

IPv4 按单个地址计数，IPv6 按 /64 聚合；IPv4 映射地址归一为 IPv4。同一 /64 的用户
共享来源额度。限流按来源统计，多个来源分散爆破同一账号仍有各自额度；安全依赖强密码。
面向公网的大规模攻击场景可结合 CDN/WAF 或基于日志的封禁工具（如 fail2ban）。

可信代理由 `auth_cookie_login_rate_trusted_proxy` 声明。默认 `auto` 模式只在直接
连接来自可信代理时解析 `X-Forwarded-For` 和 `X-Real-IP`，否则使用 `$remote_addr`。
`X-Forwarded-For` 按代理链从右向左取第一个不可信地址。未配置可信代理时，这些
请求头不会参与限流键。

经 unix socket 接收代理流量时，可配置 `auth_cookie_login_rate_trusted_proxy unix:;`
并让可信前端提供真实 IP Header，或使用 realip 的 `set_real_ip_from unix:` 配合
`real_ip_header`。`unix:` 信任所有 unix socket 直连来源，socket 权限应限制连接者。
未配置真实 IP 来源时，unix socket 请求共用一个限流桶。

需要按 CDN 特有 Header 识别客户端时，显式配置一个或多个 Header；模块按配置顺序
取第一个合法 IPv4/IPv6。显式模式下必须配置至少一个可信代理；来源不可信或没有
合法 IP 时返回 HTTP 400，不进入登录处理。

```nginx
auth_cookie_login_rate_trusted_proxy 203.0.113.0/24;
auth_cookie_login_rate_ip_header Ali-Real-Client-IP;
auth_cookie_login_rate_ip_header X-Forwarded-For;
```

两个列表指令都支持一行多个值和多行追加。子层级未配置时继承父级列表；子层级配置
自己的列表时整体替换父级；单独写 `off` 清空继承的列表。

IP 桶和 IP+用户名桶分别使用独立的共享内存区。每个区默认 1 MiB，可在 `http`
层级调整：

```nginx
auth_cookie_login_rate_zone_size 4m;
```

共享内存中保存固定长度 key 摘要和整数令牌状态，每个区容量不足时只淘汰该区最久
未使用的条目，因此用户名轮换不会重置 IP 总限额。相同大小的 reload 保留限流状态；
改变共享内存大小或完整 restart 后清空。限流状态不跨多个 Nginx 实例共享。

用户加载去重和请求查找共用区分大小写的字符串红黑树索引；重复用户名以首条为准。
本模块面向几十个用户量级的小规模认证场景。

登录与登出 URI 在同层访问控制之后执行：`satisfy`、`allow`/`deny`、
`auth_basic`、`auth_request` 等配置会先约束登录入口，
被拒绝的来源返回 403 而非登录页。

`auth_cookie_csrf` 默认开启：网页登录、Basic 认证和登出请求带 `Origin` 头时要求其
host:port 与请求 Host 一致（比较忽略 scheme，以兼容 TLS 终结代理），
`Origin: null` 与 `Sec-Fetch-Site: cross-site` 被拒绝；
无 Origin 的非浏览器客户端（如 curl）不受影响。
可配置 `auth_cookie_csrf off` 关闭该校验。

`$auth_cookie_user` 变量包含当前已认证用户名，可用于访问日志：

```nginx
log_format auth '$remote_addr user=$auth_cookie_user "$request" $status';
```

该变量保留本次请求中最近一次 Cookie 或 Basic 认证通过的用户名，包括内部重定向到
公开 location 后的日志；每个启用认证的目标 location 仍独立认证。

## htpasswd

用户文件最大 1 MiB，支持：

- `$apr1$` Apache MD5
- `$2a$`、`$2b$`、`$2y$` bcrypt

建议使用 bcrypt：

```sh
htpasswd -B /etc/nginx/htpasswd alice
```

密码哈希在 worker 中同步计算，期间同 worker 的其他连接等待。bcrypt cost 的耗时随
机器变化，本机参考值为 cost 5 约 1.4ms、10 约 39ms、12 约 156ms。推荐 cost 不超过
10；超过 10 时加载用户文件会告警，不影响启动或认证，且每个文件快照只告警一次。
登录限流约束失败认证的哈希次数；默认认证成功不计入限流，Basic 的哈希负载随持有
正确凭据的客户端请求频率增长，`auth_cookie_login_rate_refund off` 可将其一并限流。

## 验证

在本模块仓库根目录执行。单元测试需要 C 编译器和 OpenSSL 开发库；集成测试还需要
curl、openssl 命令及已静态编入本模块的 nginx 二进制。集成测试构建须启用
`--with-http_ssl_module --with-http_v2_module --with-http_realip_module --with-http_auth_request_module`；
nginx worker 须能访问测试临时目录。

```sh
# 单元测试(编译正式实现,无需构建 nginx)
make verify

# 集成与安全回归测试(需要已构建的 nginx 二进制)
make test NGINX_BIN=/absolute/path/to/nginx
```

部署前使用 `nginx -t` 检查配置。
