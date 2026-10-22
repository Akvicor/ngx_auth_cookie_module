# ngx_http_auth_cookie_module

[中文文档](README.md)

[Blog](https://www.ksyaki.com/archives/nginx-cookiedeng-lu-ren-zheng-cha-jian)

`ngx_http_auth_cookie_module` provides nginx with HMAC-signed cookie sessions and
HTTP Basic client authentication sharing the same user file and login rate limits.

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
| `auth_cookie_csrf <on\|off>` | `on` | Shared same-origin check for web login, Basic authentication, and logout |
| `auth_cookie_basic <on\|off>` | `on` | Accept preemptive HTTP Basic credentials from clients |
| `auth_cookie_login_rate <IP capacity> <IP period> <IP+username capacity> <IP+username period> \| off` | `10 1000ms 1 1000ms` | Shared IP and IP+username bucket parameters for web login POSTs and Basic authentication; `off` disables all limiting |
| `auth_cookie_login_rate_key <ip\|username\|ip_username>` | `ip_username` | Login rate limit key; `ip_username` checks the IP bucket before the IP+username bucket |
| `auth_cookie_login_rate_refund <on\|off>` | `on` | Refund reserved tokens after successful web login or Basic authentication; `off` counts successes too |
| `auth_cookie_login_rate_zone_size <size>` | `1m` | Size of each login rate limit shared memory zone; only valid at `http` level |
| `auth_cookie_login_rate_trusted_proxy <IP or CIDR or unix:...>` | Empty | Trusted proxies; supports multiple values and repeated directives |
| `auth_cookie_login_rate_ip_header <header...>` | Not set | Ordered IP headers; supports multiple values and repeated directives |

`auth_cookie_secret` is read while the configuration is loaded. If the file does not exist, a random 256-bit secret is generated and written with `0600` permissions, so `nginx -t` may also create this file. An existing file must be a regular file, contain at least 32 bytes, and grant no permissions to group or other users.

The htpasswd, secret, and custom page files support symbolic links, including
Kubernetes Secret/ConfigMap mounts. Secret ownership, permission, and size checks
apply to the target. Directories containing the secret or traversed by its link
path should be writable only by the nginx master user (root for a root-started
master). Mounted targets must also meet the secret permission requirements.

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

### HTTP Basic Compatibility

Setting `auth_cookie_user_file` enables both web login and preemptive HTTP Basic
authentication against the same user file. With `auth_cookie_basic off`, Basic
headers take no part in authentication or login rate limiting, and requests are
treated as unauthenticated and redirected to web login. Legacy clients can send an
`Authorization: Basic ...` header directly:

```sh
curl -u 'username:password' https://app.example.com/private/
```

A valid cookie takes precedence. Otherwise, valid Basic credentials grant access
and populate `$auth_cookie_user`; session cookies are issued through web login.
Basic supports the same APR1 and bcrypt hashes and configuration-time user
snapshot, refreshed on reload or restart. Internal redirects authenticate against
the destination location's user table. The original Authorization header is
preserved for upstreams and other authentication modules.

Both authentication methods share username/password validation and
`auth_cookie_csrf` checks. Usernames are limited to 128 bytes and reject NUL,
colons, CR, and LF; passwords must be nonempty and reject NUL. Form fields are
limited to 4096 bytes before URL decoding; Basic passwords use the same limit
after Base64 decoding. Basic credentials come from the request header, while
application request bodies follow the application's upload configuration.
Login/logout endpoints retain their existing body size and length requirements.

Requests without Basic credentials continue to redirect to web login. Malformed
Basic credentials, unknown users, and incorrect passwords receive 401; same-origin
check failures receive 400, login rate limit excess receives 429, and an invalid
source in explicit IP header mode receives 400. This module
sends no `WWW-Authenticate` challenge, so it does not trigger a browser's native
authentication dialog. Clients must send Basic credentials preemptively (as
`curl -u` does), rather than wait for a challenge. This module alone provides the
compatibility path; a separately configured native `auth_basic` module retains
its own challenge behavior. As with cookie authentication, a failed authentication
ends the request; after successful authentication, other access controls follow
`satisfy`.

Basic verifies passwords per request and shares `auth_cookie_login_rate` quotas
with web login POSTs; see Login Rate Limiting for accounting. By default,
successful Basic authentication does not consume quota, so clients with valid
credentials incur one password hash per request; frequently used accounts should
use APR1 or a low bcrypt cost, or configure `auth_cookie_login_rate_refund off`
to count successes as well. Internal redirects check each bucket key and rate configuration
once per request; a different authentication scope uses the destination's limits
and user table. Requests authenticated by a valid cookie use their existing
session and do not involve login quota. Use HTTPS in production.

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
base64url(user:exp:nonce).hex(OpenSSL HMAC-SHA256(secret, host + user_file + fingerprint + payload))
```

The signature is bound to the request host and user file, preventing cookies from other virtual hosts or authentication domains from being replayed. `next` accepts only site-local absolute paths or HTTP(S) URLs whose authority matches the current Host, and rejects control characters, backslashes, and protocol-relative URLs.

Redirect output preserves the original URI encoding, including `+` and `%20`.
Absolute URLs containing percent encoding in the authority are rejected. Form
fields are limited to 4096 bytes before decoding. Depending on encoding expansion,
complex original URLs longer than approximately 2.7KB may fall back to `/` (a
2505-byte URI worked in testing, while a 3005-byte URI fell back). This is not a
universal length cutoff for every URL.

Sessions are stateless on the server, allowing multiple workers to verify
signatures directly. The htpasswd file is loaded into memory while the
configuration is loaded; file changes take effect after a `reload` or restart.
Each file purpose and path is loaded once per configuration cycle and shared by
server/location configurations; a reload reads new snapshots. Issued sessions are bound to a
fingerprint of the current user's password hash, so deleting a user or changing
their password invalidates old sessions after a reload. Logging out clears the
browser cookie. Production deployments should use HTTPS.

HTTPS sites should use `auth_cookie_name __Host-auth_cookie;`. Browsers require
`__Host-` cookies to have `Secure`, `Path=/`, and host-only scope, preventing sibling
subdomains from injecting or shadowing them. The `__Host-` and `__Secure-` prefixes
(case-insensitive) require `auth_cookie_secure on`; incompatible configurations
are rejected. The default name remains `auth_cookie`.

Unknown usernames and wrong passwords produce identical pages, messages, and
status codes, but different response times. Treat usernames as public identifiers;
authentication security relies on rate limiting and strong passwords.

After login, password copies and the original in-memory request body are cleared
on a best-effort basis. TLS, HTTP/2, and other internal buffers may retain plaintext.
Keep `client_body_in_file_only off` for login locations. Core dumps may contain
recent plaintext passwords, so restrict their creation and distribution. For Basic
authentication, the module clears its password copy used for hashing; the username
and password decoded from the request header are shared with `$remote_user` and
native `auth_basic`, and remain until the request ends.

Login/logout POST bodies are limited to 8KB, excluding headers and independently
of protected application uploads. Requests with a body require `Content-Length`;
chunked requests and HTTP/2 or HTTP/3 bodies without a length receive 411. Declared
lengths above 8KB receive 413. Bodyless POSTs may omit the length: logout returns
302 and empty login returns 400, matching `Content-Length: 0`. The module limit
is independent of the application's `client_max_body_size`.

## Login Rate Limiting

The module limits POST requests to the login URI and Basic authentication on
protected resources, using the two-level `ip_username` mode by default. The IP bucket allows
10 requests per source IP every 1000 ms, while the IP+username bucket allows one request per source IP + username
pair every 1000 ms. Each web login POST and Basic authentication reserves tokens
before password verification and refunds them after successful verification
(with `auth_cookie_login_rate_refund off`, successes keep the charge).
Wrong passwords, unknown users, malformed forms or credentials, and CSRF failures
keep the charge. Reservation bounds concurrent attempts by the same quota; once
exhausted, correct passwords also receive 429 until tokens recover.
GET/HEAD requests for the login page, logout POSTs, and cookie-authenticated
resource requests do not. Excess requests receive HTTP 429, with the login page
for web login or a standard error response for Basic. State is shared by all
workers and isolated per effective authentication configuration within the same
nginx instance.

```nginx
auth_cookie_login_rate 10 1m 1 10s;    # 10 requests/minute per IP, 6 requests/minute per IP+username
auth_cookie_login_rate_key ip_username;
```

The `ip` mode uses the first two parameters to limit each IP. The `username` mode
uses the last two parameters to limit each source IP + username. The `ip_username`
mode checks the IP bucket with the first two parameters and then checks the source
IP + username bucket with the last two parameters. CSRF failures, empty credentials,
and attempts without a valid username fall back to the source IP key. Token
accounting uses integer arithmetic only.

IPv4 is counted per address, IPv6 per /64 prefix, and IPv4-mapped addresses are
normalized to IPv4. Users in one /64 share the source allowance. Distributed
attempts against one account retain separate allowances per source; use strong
passwords and, for large public-facing attacks, combine with CDN/WAF protection
or log-based blocking tools such as fail2ban.

Trusted proxies are declared with `auth_cookie_login_rate_trusted_proxy`. The
default `auto` mode parses `X-Forwarded-For` and `X-Real-IP` only when the direct
connection comes from a trusted proxy; otherwise it uses `$remote_addr`.
`X-Forwarded-For` is evaluated from right to left, selecting the first untrusted
address. Without a trusted proxy, those headers do not participate in the rate
limit key.

For traffic forwarded over unix sockets, configure
`auth_cookie_login_rate_trusted_proxy unix:;` and have the trusted frontend supply
real client IP headers, or use realip's `set_real_ip_from unix:` with
`real_ip_header`. `unix:` trusts all direct unix socket sources, so socket
permissions should restrict who can connect. Without real client IP resolution,
unix socket requests share one rate limit bucket.

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

Loading deduplication and request lookups share a case-sensitive string red-black
tree index. Duplicate usernames keep the first entry. The module targets
small-scale authentication with tens of users.

Login and logout URIs run after same-level access controls: `satisfy`,
`allow`/`deny`, `auth_basic`, and `auth_request` constrain the login entry
first, and rejected sources receive 403 instead of the login page.

`auth_cookie_csrf` is enabled by default: web login, Basic authentication, and logout carrying an
`Origin` header must match the request Host in host:port (the comparison
ignores the scheme, so TLS-terminating proxies work), while `Origin: null` and
`Sec-Fetch-Site: cross-site` are rejected. Non-browser clients without an
`Origin` header (such as curl) are unaffected. Configure `auth_cookie_csrf off`
to disable the check.

The `$auth_cookie_user` variable contains the currently authenticated username and can be used in access logs:

```nginx
log_format auth '$remote_addr user=$auth_cookie_user "$request" $status';
```

The variable retains the last successfully authenticated Cookie or Basic username
for this request, including logs after internal redirects to public locations.
Each protected destination location still authenticates independently.

## htpasswd

The user file is limited to 1 MiB and supports:

- `$apr1$` Apache MD5
- `$2a$`, `$2b$`, and `$2y$` bcrypt

bcrypt is recommended:

```sh
htpasswd -B /etc/nginx/htpasswd alice
```

Password hashing is synchronous in the worker, blocking its other connections
until completion. Costs vary by hardware; local measurements were approximately
1.4ms at bcrypt cost 5, 39ms at cost 10, and 156ms at cost 12. A cost no greater
than 10 is recommended. Higher costs generate a warning once per loaded user file
snapshot without rejecting startup or authentication. Login rate limits bound
hashing for failed attempts. By default, successful authentication is not counted,
so Basic hashing load grows with the request rate of clients holding valid
credentials; `auth_cookie_login_rate_refund off` limits those requests as well.

## Verification

Run from this module's repository root. Unit tests require a C compiler and OpenSSL
development libraries. Integration tests also require curl, the openssl command,
and an nginx binary with this module statically compiled in. The integration test
build requires `--with-http_ssl_module --with-http_v2_module --with-http_realip_module --with-http_auth_request_module`.
The nginx worker must have access to the test temporary directory.

```sh
# Unit tests against the real implementation (no nginx build required)
make verify

# Integration and security regression tests (require a built nginx binary)
make test NGINX_BIN=/absolute/path/to/nginx
```

Check the deployed configuration with `nginx -t`.
