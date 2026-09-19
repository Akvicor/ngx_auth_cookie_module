# ngx_http_auth_cookie_module

`ngx_http_auth_cookie_module` provides nginx with session authentication based on HMAC-signed cookies.

## Build

The module depends on nginx's `ngx_crypt()`, libcrypt, and OpenSSL. Add the following when configuring nginx:

```sh
./configure \
  --with-http_ssl_module \
  --add-module=../ngx_auth_cookie_module
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
| `auth_cookie_csrf <on\|off>` | `on` | Same-origin check for login/logout POST requests |
| `auth_cookie_login_rate <IP capacity> <IP period> <IP+username capacity> <IP+username period> \| off` | `10 1000ms 1 1000ms` | Login POST IP bucket and IP+username bucket parameters; `off` disables all limiting |
| `auth_cookie_login_rate_key <ip\|username\|ip_username>` | `ip_username` | Login rate limit key; `ip_username` checks the IP bucket before the IP+username bucket |
| `auth_cookie_login_rate_zone_size <size>` | `1m` | Size of each login rate limit shared memory zone; only valid at `http` level |
| `auth_cookie_login_rate_trusted_proxy <IP or CIDR...>` | Empty | Trusted proxies; supports multiple values and repeated directives |
| `auth_cookie_login_rate_ip_header <header...>` | Not set | Ordered IP headers; supports multiple values and repeated directives |

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

Dynamic values are HTML-escaped. Placeholders should appear in text nodes or
double-quoted attributes. The login form must use POST and submit `username`,
`password`, and an optional `next` field. Text inside replacement values is
never re-interpreted as a placeholder.

## Sessions and Security Boundaries

The cookie format is:

```text
base64url(user:exp:nonce).hex(OpenSSL HMAC-SHA256(secret, host + user_file + payload))
```

The signature is bound to the request host and user file, preventing cookies from other virtual hosts or authentication domains from being replayed. `next` accepts only site-local absolute paths or HTTP(S) URLs whose authority matches the current Host, and rejects control characters, backslashes, and protocol-relative URLs.

Sessions are stateless on the server, allowing multiple workers to verify
signatures directly. The htpasswd file is loaded into memory while the
configuration is loaded; file changes take effect after a `reload` or restart.
Every server/location that enables authentication loads the file on its own,
including locations that inherit the same file. Issued sessions are bound to a
fingerprint of the current user's password hash, so deleting a user or changing
their password invalidates old sessions after a reload. Logging out clears the
browser cookie. Production deployments should use HTTPS.

## Login Rate Limiting

By default, the module limits only POST requests to the login URI and uses the
two-level `ip_username` mode. The IP bucket allows 10 requests per source IP every
1000 ms, while the IP+username bucket allows one request per source IP + username
pair every 1000 ms. Successful attempts, wrong passwords, malformed forms, and CSRF
failures consume tokens; GET/HEAD requests for the login page and logout POST
requests do not. Excess requests receive HTTP 429 with the login page and an error
message. State is shared by all workers and isolated per effective authentication
configuration within the same nginx instance.

```nginx
auth_cookie_login_rate 10 1m 1 10s;    # 10 requests/minute per IP, 6 requests/minute per IP+username
auth_cookie_login_rate_key ip_username;
```

The `ip` mode uses the first two parameters to limit each IP. The `username` mode
uses the last two parameters to limit each source IP + username. The `ip_username`
mode checks the IP bucket with the first two parameters and then checks the source
IP + username bucket with the last two parameters. Login POST requests without a
valid username fall back to the source IP key. Token accounting uses integer
arithmetic only.

Trusted proxies are declared with `auth_cookie_login_rate_trusted_proxy`. The
default `auto` mode parses `X-Forwarded-For` and `X-Real-IP` only when the direct
connection comes from a trusted proxy; otherwise it uses `$remote_addr`.
`X-Forwarded-For` is evaluated from right to left, selecting the first untrusted
address. Without a trusted proxy, those headers do not participate in the rate
limit key.

To use CDN-specific headers, configure one or more headers explicitly. The module
uses the first valid IPv4/IPv6 address in the configured order. Explicit mode
requires at least one trusted proxy; untrusted sources or requests without a valid
IP receive HTTP 400 before login processing.

```nginx
auth_cookie_login_rate_trusted_proxy 203.0.113.0/24;
auth_cookie_login_rate_ip_header Ali-Real-Client-IP;
auth_cookie_login_rate_ip_header X-Forwarded-For;
```

Both list directives accept multiple values on one line and may be repeated. A
child level inherits the parent list when it has none; configuring a list replaces
the inherited list; a standalone `off` clears it.

The IP bucket and IP+username bucket use separate shared memory zones. Each zone
defaults to 1 MiB and can be adjusted at `http` level:

```nginx
auth_cookie_login_rate_zone_size 4m;
```

Each zone stores fixed-length key digests and integer token state. When a zone is
full, only its least recently used entries are evicted, so username rotation cannot
reset the overall IP limit. A reload with the same zone size preserves state;
changing the size or restarting nginx clears it. State is not shared across
multiple nginx instances.

User lookup is a linear scan; the module targets small-scale authentication
with tens of users.

Login and logout URIs run after same-level access controls: `satisfy`,
`allow`/`deny`, `auth_basic`, and `auth_request` constrain the login entry
first, and rejected sources receive 403 instead of the login page.

`auth_cookie_csrf` is enabled by default: a login/logout POST carrying an
`Origin` header must match the request Host in host:port (the comparison
ignores the scheme, so TLS-terminating proxies work), while `Origin: null` and
`Sec-Fetch-Site: cross-site` are rejected. Non-browser clients without an
`Origin` header (such as curl) are unaffected. Configure `auth_cookie_csrf off`
to disable the check.

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

After configuring the nginx source tree, run:

```sh
make
```

Check the deployed configuration with `nginx -t`.
