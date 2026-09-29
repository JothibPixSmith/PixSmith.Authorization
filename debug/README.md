# Debugging in containers

Brings up Postgres and the auth server as containers, then attaches the VS Code
debugger to the server process — the VS Code equivalent of Visual Studio's
`Container (Dockerfile)` launch profile.

```
debug/
├── start.sh       # network → Postgres → dev keys → debug image → server, waits until ready
├── stop.sh        # tear down (server only by default)
├── provision.sh   # signed tenant-provisioning requests using the dev keys
├── keys/          # generated on first run — gitignored, never leaves this machine
└── README.md
```

---

## Press F5

Pick **Attach to Auth Server (container)** in the Run panel. That is the whole
workflow — there is no process picker and nothing to select.

The configuration's `preLaunchTask` runs `debug/start.sh`, which does not return
until the server is answering with a valid discovery document. The debugger then
attaches to **PID 1** directly.

Pinning the PID is safe because the image uses an exec-form `ENTRYPOINT`, so
`dotnet` is PID 1 with no shell wrapper. `start.sh` asserts that before reporting
ready, and fails with an explicit message if it ever stops being true — attaching
to the wrong process presents as "breakpoints never hit", which is a miserable
thing to diagnose.

Set breakpoints anywhere in the server projects. They bind because the debug image
is published in **Debug** configuration with PDBs, and `sourceFileMap` maps the
container's `/src` build path back onto the workspace.

### Or from a terminal

```bash
./debug/start.sh                       # bring the stack up
./debug/stop.sh                        # remove the server container
./debug/stop.sh --all                  # ...and stop Postgres
./debug/stop.sh --purge                # ...and DELETE the volumes (prompts)
```

`start.sh` is idempotent. Postgres is reused if it is already running, restarted
if stopped, and created if absent. Only the server container is recreated every
run, because that is the one holding your code.

### Or with Compose

```bash
docker compose -f docker-compose.yml -f docker-compose.debug.yml up --build
```

[docker-compose.debug.yml](../docker-compose.debug.yml) is an overlay declaring
only what differs — build target, container name, environment. Everything else
comes from the base file, so the two cannot drift apart.

---

## Creating tenants locally

Tenant provisioning requires a quorum of offline signatures and **fails closed** when none
are enrolled, so without keys the debug stack cannot create a tenancy at all.

`start.sh` therefore generates three development keypairs into `debug/keys/` on first run
(threshold 2, one spare — the smallest configuration that is both safe and operable) and
enrols the public halves with the container. The directory is gitignored; the private keys
never leave your machine.

```bash
./debug/provision.sh create '{"name":"Acme Corp","description":"Test tenancy"}'
./debug/provision.sh delete <tenant-id>
./debug/provision.sh raw PUT /api/admin/tenants/<id> '{"name":"Renamed"}'
```

The helper obtains an admin token, signs the canonical payload with two dev keys, and sends
the request. Override the signer set to exercise the quorum:

```bash
PROVISION_SIGNERS="dev-alice"           ./debug/provision.sh create '{"name":"X"}'  # 403
PROVISION_SIGNERS="dev-alice dev-alice" ./debug/provision.sh create '{"name":"X"}'  # 403
PROVISION_SIGNERS="dev-bob dev-carol"   ./debug/provision.sh create '{"name":"X"}'  # 201
```

> **These keys are for development only.** In production the ceremony is the point: each
> operator generates their key on their own machine with `tools/provision-keygen.sh`, holds
> it offline, and signs independently. `provision.sh` holds every key at once, which is
> precisely what the real control exists to prevent — hence `debug/keys/` and nothing else.
> See [docs/TENANT-PROVISIONING.md](../docs/TENANT-PROVISIONING.md).

---

## How the debug image is built

There is **no separate debug Dockerfile.** The root [Dockerfile](../Dockerfile)
has a `debug` target that reuses the same `build` stage as production:

```bash
docker build --target debug --build-arg BUILD_CONFIGURATION=Debug .
```

`BUILD_CONFIGURATION` defaults to `Release`, so a plain `docker build .` still
produces the production image unchanged. The debug target differs in four ways,
each of them a reason it must never be deployed:

| | `runtime` (production) | `debug` |
|---|---|---|
| Base image | `aspnet:10.0` | `sdk:10.0` — ships compilers |
| Configuration | Release | Debug, with PDBs |
| Debugger | none | `vsdbg` at `/vsdbg` |
| Environment | Production | Development — Swagger, detailed errors |

---

## What start.sh checks, and why

Each step exists because skipping it produces a confusing failure later:

1. **Network** — created if missing. Postgres is attached with the alias
   `postgres`, because that is the hostname in the connection string. A container
   on the wrong network is reachable from the host but invisible to the server.
2. **Postgres health** — waits for `pg_isready`, not merely a running container.
   EF Core migrations run at startup and will fail against a database that is
   still initialising.
3. **Credentials** — connects as the application role before starting the server,
   so a password mismatch reads as a password mismatch instead of surfacing as an
   EF migration stack trace half a minute later.
4. **Provisioning keys** — generated and enrolled before the server starts, because the
   control fails closed and an unconfigured server refuses to create any tenancy.
5. **Discovery returns 200** — not just an open socket. OpenIddict answers on the
   port well before it will serve protocol requests, and a 400 there means the
   OIDC endpoints are unusable even though the process is alive.

---

## Gotchas

**Plain HTTP.** The debug container serves HTTP on 8080. OpenIddict refuses
protocol requests over HTTP, so `DisableTransportSecurityRequirement()` is enabled
**in Development only** ([InfrastructureServiceExtensions.cs](../src/AuthServer/AuthServer.API/InfrastructureServiceExtensions.cs)).
Production keeps the requirement, and `UseForwardedHeaders` lets OpenIddict see
the original `https` scheme behind a TLS-terminating proxy.

**Postgres passwords are baked into the volume.** The init script only runs
against an empty data directory. Changing `APP_DB_PASSWORD` in `.env` after the
first run will not change the role's password — `start.sh` detects this and tells
you the `ALTER ROLE` to run.

**Rebuilds are image rebuilds.** There is no Fast-mode equivalent here: editing
code means `start.sh` rebuilds the image and recreates the container. Layer caching
keeps that to a few seconds, but it is not the sub-second edit-and-continue you get
debugging locally. For a tight inner loop, use the plain **Auth Server (API)**
launch configuration and point it at the containerised Postgres:

```
ConnectionStrings__DefaultConnection=Host=localhost;Port=5432;Database=pixsmith_auth;Username=pixsmith_app;Password=<APP_DB_PASSWORD>
Database__Provider=Postgres
```

---

## Verified

Exercised end to end on this machine:

- `start.sh` brings the stack from nothing to ready, and is safe to re-run
- both Dockerfile targets build; `--target runtime` is unaffected by the debug work
- the debug image contains `vsdbg` and 9 PDBs
- the server reaches Postgres over the network alias and issues a working token
  (`grant_type=password` → 200, correct `sub` and roles)
- `start.sh` asserts PID 1 is the app, vsdbg is present, and PDBs shipped
- **auto-attach works**: driving vsdbg over `docker exec -i` — the exact transport
  `pipeTransport` uses — a DAP `initialize` and then `attach` to `processId: 1`
  both returned `success: true`, with no process picker involved

- **breakpoints bind and hit**, confirmed in VS Code against this configuration —
  so the `sourceFileMap` of `/src` → workspace is correct

That last point depends on the container build path staying `/src`. If the
`Dockerfile`'s `WORKDIR` changes, or a `PathMap` / `DeterministicSourcePaths`
setting is ever added to the build, the mapping has to change with it — the symptom
is breakpoints showing as hollow circles.
