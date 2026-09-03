# ngx_http_auth_cookie_module

`ngx_http_auth_cookie_module` 为 nginx 提供基于 HMAC 签名 Cookie 的会话认证。

## 构建

模块依赖 nginx `ngx_crypt()`、libcrypt 与 OpenSSL。配置 nginx 时加入：

```sh
./configure \
  --with-http_ssl_module \
  --add-module=../modules/ngx_auth_cookie_module
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

动态值会进行 HTML 转义。占位符应放在文本节点或带双引号的属性中。登录表单须使用 POST，并提交 `username`、`password` 与可选的 `next` 字段。

## 会话与安全边界

Cookie 格式为：

```text
base64url(user:exp:nonce).hex(OpenSSL HMAC-SHA256(secret, host + user_file + payload))
```

签名绑定请求 host 与用户文件，来自其他虚拟主机或认证域的 Cookie 无法重放。`next` 只接受站内绝对路径或 authority 与当前 Host 一致的 HTTP(S) URL，并拒绝控制字符、反斜杠和协议相对 URL。

会话无服务端状态，多 worker 可直接验签。htpasswd 在配置加载时读入内存，文件修改在 `reload` 或重启后生效。签发绑定当前用户密码哈希指纹，删除用户或改密并 reload 后旧会话失效。登出会清除浏览器 Cookie。生产环境应使用 HTTPS，并可通过 nginx `limit_req` 为登录 URI 配置速率限制。

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

```sh
../../tests/ngx_auth_cookie_module/run-hmac.sh
../../tests/ngx_auth_cookie_module/integration.sh /path/to/nginx
```

