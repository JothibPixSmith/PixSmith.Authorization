# Staging stack

A production-shaped copy of the auth server on your machine. Use it to see what production
does: pen tests, checking a release build, anything the debug stack can't tell you because
Development deliberately relaxes it.

```bash
./staging/start.sh          # build, start, and verify
./staging/stop.sh           # remove the server and proxy (Postgres keeps running)
./staging/stop.sh --purge   # delete all staging data and secrets
./staging/provision.sh create '{"name":"Acme Corp"}'   # signed tenant provisioning
```

In VS Code: **Tasks: Run Task** → `staging: start stack` / `staging: stop stack`.

## How it differs from the debug stack

| | Debug (`debug/start.sh`) | Staging (`staging/start.sh`) |
|---|---|---|
| Image | `debug` target: SDK, vsdbg, Debug build | `runtime` target: Release, no SDK, no debugger |
| Environment | `Development` | `Staging` |
| URL | `http://localhost:8080` | `https://localhost:8443` through an nginx TLS proxy |
| HTTPS requirement | off | **on** |
| Token certificates | OpenIddict dev certificates | real PKCS#12 certificates, stable across restarts |
| Forwarded headers | trusted from anyone | trusted only from the proxy's fixed IP |
| HSTS, Swagger | no HSTS, Swagger on | HSTS on, Swagger off |
| Postgres | `pixsmith-postgres`, on the host at `:5432` | `pixsmith-staging-postgres`, not reachable from the host |
| Secrets | `.env` | generated into `staging/secrets/` (gitignored) |

The two stacks are fully separate (networks, databases, volumes, keys), so both can run at
once.

`start.sh` only reports ready after checking these:
- the issuer is `https://`
- plain HTTP sent straight to the app with a faked `X-Forwarded-Proto: https` is refused
- the environment is Staging
- the image has no SDK or debugger
- Swagger is not served

## Using it

- **Browser:** the TLS certificate is self-signed, so expect one warning.
- **curl:** pass `--cacert staging/secrets/tls.crt`.
- **Admin account:** `admin@pixsmith.local`, with the password in `staging/secrets/admin-password`.
- **Pen tests:** target `https://localhost:8443/`. The test fixtures (a test company, the
  `pentest-*` clients and users, and the temporary `oidf-conformance` client) live in the
  pen-testing repository: `PixSmith.PenTesting/tools/staging/seed-fixtures.py`, which writes
  its credentials there too. It expects this repo next to it, or at `PIXSMITH_AUTH_REPO`.
- **OIDF conformance suite:** its OIDC certification plans send no `code_challenge`. Every
  other client requires PKCE, so the suite runs against a temporary exempt client, which
  this server only allows when started with `STAGING_ALLOW_PKCE_EXEMPT=true ./staging/start.sh`.
  Create and delete that client with the fixtures script's `oidf-client create|delete`, then
  restart without the variable. The exempt client may leave PKCE out, but `plain` is still
  refused. If you forget the delete, restarting without the variable puts PKCE back on it anyway.
- **`http://localhost:8090`** goes straight to the app, skipping the proxy. It exists only so
  you can confirm the app refuses protocol requests there. A real deployment must not expose
  this port.

## Limits

- **HSTS** never appears on `localhost`. ASP.NET Core leaves localhost out on purpose, so a
  browser doesn't get pinned to HTTPS for every local port. Seeing it needs a real hostname.
- **Self-signed TLS** is fine for staging but not for production, where you need a real
  certificate.
- **Email** goes to the same stub SMTP settings as Development (`localhost:1025`).

## Rate limits during a pen test

The credential endpoints (`/connect/token`, the login form, registration, password reset) are
capped at 20 requests per 60 seconds **per client IP per endpoint**. Staging runs the same
limits as production so the stack stays representative, which means a brute-force or
credential-stuffing run will start getting `429` with a `Retry-After` — that is the control
working.

If you are testing something else and the limiter is in the way, raise or remove it:

```bash
RATE_LIMIT_PERMITS=100000 ./staging/start.sh     # effectively off, middleware still in path
RATE_LIMITING_ENABLED=false ./staging/start.sh   # middleware bypassed entirely
```

Buckets are per endpoint, so exhausting the token endpoint does not throttle password resets
from the same address. Partitioning is by client IP, which is only meaningful because the
server refuses to believe `X-Forwarded-For` from anyone but the configured proxy — the stack
asserts that at startup.

## Refresh-token lifetimes during a pen test

A chain of refresh tokens dies 30 days after the original grant however often it is refreshed,
and any one token dies after 14 days unused. Staging runs those production values, which makes
the absolute cap true but unobservable: nothing is going to wait a month to see it.

Both are overridable, and `start.sh` warns on the way out when they are not production values:

```bash
# Reach the cap in two minutes. Refreshes succeed, then answer invalid_grant.
STAGING_REFRESH_ABSOLUTE_SECONDS=120 ./staging/start.sh

# No idle timeout: every refresh token is pinned to the original grant's deadline, so exp is
# identical before and after a refresh. The cheapest way to show the cap exists at all.
STAGING_REFRESH_SLIDING_SECONDS=0 ./staging/start.sh

./staging/start.sh                 # production values again
```

Two things to know:

- **Re-authenticate after changing them.** The deadline is stamped into the refresh token at
  the grant, so a token issued under the old setting keeps the old deadline. Restarting the
  stack does not move it — getting a fresh one does.
- **`STAGING_REFRESH_ABSOLUTE_SECONDS=0` is refused.** The server reads a non-positive cap as
  "unset" and falls back to 30 days, so accepting 0 here would hand you a month-long cap when
  you asked for none. Use a large number if that is what you want.

Confirmed on this stack with a two-minute cap: refreshes at 0, 20, 40, 60, 80 and 100 seconds
all returned 200, and the one at 120 seconds returned `400 invalid_grant`.

## Container engine

These scripts use **podman** by default. `CONTAINER_ENGINE=docker ./staging/start.sh` switches
back; use the same engine for `stop.sh`, since the two keep separate containers, images and
networks and the wrong one silently finds nothing to stop.

Three podman-specific details are handled in the scripts, and are worth knowing if you edit them:

- **Images are built with `--format docker`.** Podman's default OCI format silently discards
  `HEALTHCHECK`, and the Postgres readiness wait depends on it — without the flag the stack hangs
  at "waiting for health" and then fails.
- **Remote images are fully qualified** (`docker.io/library/nginx:...`). Podman searches
  `registry.fedoraproject.org` and `registry.access.redhat.com` before `docker.io` and prompts
  when a short name is ambiguous, which would hang a non-interactive run.
- **Locally built images carry a `localhost/` prefix**, which is where podman stores them, so
  `image inspect` and `run` agree about what exists.

Rootless podman is fine: the proxy's static IP on the custom network works under netavark, and
every published port is above 1024.
