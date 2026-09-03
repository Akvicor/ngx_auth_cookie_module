# ngx_http_auth_cookie_module

`ngx_http_auth_cookie_module` provides nginx with session authentication based on HMAC-signed cookies.

## Build

The module depends on nginx's `ngx_crypt()`, libcrypt, and OpenSSL. Add the following when configuring nginx:

```sh
./configure \
  --with-http_ssl_module \
  --add-module=../modules/ngx_auth_cookie_module
```

## Configuration

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

| Directive | Default | Description |
| --- | --- | --- |
| `auth_cookie_user_file <path\|off>` | `off` | htpasswd user file; setting a path enables authentication, while `off` in a child location disables inherited authentication |
| `auth_cookie_page <basic\|premium\|absolute path>` | `basic` | Login page template |
| `auth_cookie_name <name>` | `auth_cookie` | Cookie name |
| `auth_cookie_secure <on\|off>` | `on` | Sets the cookie's `Secure` attribute |
| `auth_cookie_secret <path>` | `/etc/nginx/auth_cookie.secret` | HMAC secret file |
| `auth_cookie_session_ttl <time>` | `12h` | Session lifetime; must be greater than zero |
| `auth_cookie_title <text>` | `Login` | Login page title |
| `auth_cookie_login_uri <uri>` | `/_login` | Login URI |
| `auth_cookie_logout_uri <uri>` | Not set | POST logout URI |

`auth_cookie_secret` is read while the configuration is loaded. If the file does not exist, a random 256-bit secret is generated and written with `0600` permissions, so `nginx -t` may also create this file. An existing file must be a regular file, contain at least 32 bytes, and grant no permissions to group or other users.

### Location-Level Configuration

The login URI must resolve to the same location configuration. A prefix location can be configured as follows:

```nginx
location /private/ {
    auth_cookie_user_file /etc/nginx/private.htpasswd;
    auth_cookie_login_uri /private/_login;
    proxy_pass http://127.0.0.1:3080;
}
```

Server-level configuration can use the default `/_login` directly.

## Custom Pages

Pages specified by an absolute path are read while the configuration is loaded. The template size is limited to 128 KiB, and rendered output is limited to 512 KiB. File changes take effect after a `reload` or restart. Templates support the following placeholders:

- `{{title}}`
- `{{error}}`
- `{{next}}`
- `{{action}}`

Dynamic values are HTML-escaped. Placeholders should appear in text nodes or double-quoted attributes. The login form must use POST and submit `username`, `password`, and an optional `next` field.

## Sessions and Security Boundaries

The cookie format is:

```text
base64url(user:exp:nonce).hex(OpenSSL HMAC-SHA256(secret, host + user_file + payload))
```

The signature is bound to the request host and user file, preventing cookies from other virtual hosts or authentication domains from being replayed. `next` accepts only site-local absolute paths or HTTP(S) URLs whose authority matches the current Host, and rejects control characters, backslashes, and protocol-relative URLs.

Sessions are stateless on the server, allowing multiple workers to verify signatures directly. The htpasswd file is loaded into memory while the configuration is loaded; file changes take effect after a `reload` or restart. Issued sessions are bound to a fingerprint of the current user's password hash, so deleting a user or changing their password invalidates old sessions after a reload. Logging out clears the browser cookie. Production deployments should use HTTPS and can configure rate limiting for the login URI with nginx's `limit_req`.

The `$auth_cookie_user` variable contains the currently authenticated username and can be used in access logs:

```nginx
log_format auth '$remote_addr user=$auth_cookie_user "$request" $status';
```

## htpasswd

The user file is limited to 1 MiB and supports:

- `$apr1$` Apache MD5
- `$2a$`, `$2b$`, and `$2y$` bcrypt

bcrypt is recommended:

```sh
htpasswd -B /etc/nginx/htpasswd alice
```

## Verification

```sh
../../tests/ngx_auth_cookie_module/run-hmac.sh
../../tests/ngx_auth_cookie_module/integration.sh /path/to/nginx
```

