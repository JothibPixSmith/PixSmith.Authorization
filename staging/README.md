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
