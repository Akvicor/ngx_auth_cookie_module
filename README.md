# ngx_http_auth_cookie_module

`ngx_http_auth_cookie_module` 为 nginx 提供基于 HMAC 签名 Cookie 的会话认证。

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
    # auth_cookie_login_rate 10 1000ms 1 1000ms;
    # auth_cookie_login_rate_key ip_username;
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
| `auth_cookie_csrf <on\|off>` | `on` | 登录/登出 POST 的同源校验 |
| `auth_cookie_login_rate <IP容量> <IP周期> <IP+用户名容量> <IP+用户名周期> \| off` | `10 1000ms 1 1000ms` | 登录 POST 的 IP 桶和 IP+用户名桶参数；`off` 关闭全部限流 |
| `auth_cookie_login_rate_key <ip\|username\|ip_username>` | `ip_username` | 登录限流统计键；`ip_username` 先检查 IP 桶再检查 IP+用户名桶 |
| `auth_cookie_login_rate_zone_size <size>` | `1m` | 每个登录限流共享内存区的容量，只能在 `http` 层级配置 |
| `auth_cookie_login_rate_trusted_proxy <IP或CIDR...>` | 空 | 可信代理，可多行或多值配置 |
| `auth_cookie_login_rate_ip_header <header...>` | 未设置 | 显式 IP Header 顺序，可多行或多值配置 |

`auth_cookie_secret` 在配置加载阶段读取。文件不存在时会生成 256 位随机密钥并以 `0600` 写入，因此 `nginx -t` 也可能创建该文件。已有文件须为普通文件、至少 32 字节，且不能向 group/other 授权。

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
base64url(user:exp:nonce).hex(OpenSSL HMAC-SHA256(secret, host + user_file + payload))
```

签名绑定请求 host 与用户文件，来自其他虚拟主机或认证域的 Cookie 无法重放。`next` 只接受站内绝对路径或 authority 与当前 Host 一致的 HTTP(S) URL，并拒绝控制字符、反斜杠和协议相对 URL。

会话无服务端状态，多 worker 可直接验签。htpasswd 在配置加载时读入内存，
文件修改在 `reload` 或重启后生效；每个启用认证的 server/location 配置
在加载时各自读取文件（包括继承同一文件的 location）。
签发绑定当前用户密码哈希指纹，删除用户或改密并 reload 后旧会话失效。
登出会清除浏览器 Cookie。生产环境应使用 HTTPS。

## 登录限流

模块默认只限制登录 URI 的 POST，并使用 `ip_username` 两级限流。IP 桶默认为每个来源
10 次/1000ms，IP+用户名桶默认为每个 IP+用户名组合 1 次/1000ms。成功、密码错误、
表单错误和 CSRF 失败的登录 POST 都消耗令牌；GET/HEAD 登录页和登出 POST 不计入。
超限返回 HTTP 429，并复用登录页显示错误。限流状态由全部 worker 共享，同一个
Nginx 实例内按认证配置隔离。

```nginx
auth_cookie_login_rate 10 1m 1 10s;    # 每个 IP 10 次/分钟，每个 IP+用户名 6 次/分钟
auth_cookie_login_rate_key ip_username;
```

`ip` 模式使用前两参数限制 IP；`username` 模式使用后两参数限制来源 IP + 用户名；
`ip_username` 模式先用前两参数检查 IP，再用后两参数检查来源 IP + 用户名。
无法取得有效用户名的登录 POST 回退到来源 IP。令牌和恢复周期都使用整数计算，不使用浮点。

可信代理由 `auth_cookie_login_rate_trusted_proxy` 声明。默认 `auto` 模式只在直接
连接来自可信代理时解析 `X-Forwarded-For` 和 `X-Real-IP`，否则使用 `$remote_addr`。
`X-Forwarded-For` 按代理链从右向左取第一个不可信地址。未配置可信代理时，这些
请求头不会参与限流键。

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

用户查找为线性扫描，本模块面向几十个用户量级的小规模认证场景。

登录与登出 URI 在同层访问控制之后执行：`satisfy`、`allow`/`deny`、
`auth_basic`、`auth_request` 等配置会先约束登录入口，
被拒绝的来源返回 403 而非登录页。

`auth_cookie_csrf` 默认开启：登录/登出 POST 带 `Origin` 头时要求其
host:port 与请求 Host 一致（比较忽略 scheme，以兼容 TLS 终结代理），
`Origin: null` 与 `Sec-Fetch-Site: cross-site` 被拒绝；
无 Origin 的非浏览器客户端（如 curl）不受影响。
可配置 `auth_cookie_csrf off` 关闭该校验。

`$auth_cookie_user` 变量包含当前已认证用户名，可用于访问日志：

```nginx
log_format auth '$remote_addr user=$auth_cookie_user "$request" $status';
```

## htpasswd

用户文件最大 1 MiB，支持：

- `$apr1$` Apache MD5
- `$2a$`、`$2b$`、`$2y$` bcrypt

建议使用 bcrypt：

```sh
htpasswd -B /etc/nginx/htpasswd alice
```

## 验证

在 nginx 源码目录中完成配置后执行：

```sh
make
```

部署前使用 `nginx -t` 检查配置。
