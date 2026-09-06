# Docker

Runs the auth server against PostgreSQL.

```
docker/
├── .env.example            # copy to ../.env and fill in
├── postgres/
│   ├── Dockerfile          # thin layer over postgres:17-alpine
│   └── init/
│       └── 01-create-app-role.sh   # creates the least-privilege app role
└── README.md
```

The auth server's own image is built from the `Dockerfile` at the repository root.

---

## Quick start

```bash
cp docker/.env.example .env      # then edit the passwords
docker compose up --build
```

The auth server comes up on <http://localhost:8080>. EF Core migrations run automatically at
startup, so the schema is created on the first boot — there is no separate migration step.

Postgres is published on `127.0.0.1:5432` only, so it is reachable from your machine but not
from the network. If you never need `psql` from the host, delete the `ports:` block on the
`postgres` service entirely.

---

## Running Postgres on its own

Without the Compose plugin, or when you want the database up before the auth server exists:

```bash
docker network create pixsmith-authorization        # once

docker build -t pixsmith/postgres:17 docker/postgres

docker run -d --name pixsmith-postgres \
  --env-file .env \
  --network pixsmith-authorization \
  --network-alias postgres \
  -p 127.0.0.1:5432:5432 \
  -v pixsmith-postgres-data:/var/lib/postgresql/data \
  pixsmith/postgres:17
```

`--network-alias postgres` is not optional. The auth server's connection string uses
`Host=postgres`, which is the *service* name Compose would assign — the container name
`pixsmith-postgres` does not resolve to it. Without the alias, a container started this way is
reachable from the host but invisible to the auth server under the hostname it actually dials.

Verify both halves:

```bash
docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{$v.Aliases}}{{end}}' pixsmith-postgres
docker run --rm --network pixsmith-authorization postgres:17-alpine getent hosts postgres
```

> **If you created the network by hand, tell Compose about it.** `docker-compose.yml` defaults
> to `external: false`, meaning Compose expects to create the network itself and will refuse a
> pre-existing one that lacks its labels. Set `DOCKER_NETWORK_EXTERNAL=true` in `.env` so it
> joins yours instead of trying to create it.

`docker run` has no equivalent of `depends_on: service_healthy`. If you start the auth server
manually too, wait for `docker inspect -f '{{.State.Health.Status}}' pixsmith-postgres` to
report `healthy` first, or startup migrations will fail against a database that is still
initialising.

---

## Why there is an application role

`POSTGRES_USER` is a superuser and exists for administration. The auth server connects as
`APP_DB_USER` instead, a role that:

- owns the `public` schema in its own database, so EF Core migrations can create tables
- cannot connect to any other database on the server
- cannot create roles, and is not a superuser

A leaked connection string therefore exposes the auth database and nothing else. Give the two
roles **different** passwords — reusing one makes the separation decorative.

Keep quote characters (`'` and `"`) out of `APP_DB_PASSWORD`. The init script handles them
safely, but the value also ends up inside an ADO.NET connection string where quoting rules are
their own adventure. Long and alphanumeric beats short and clever.

---

## The init scripts run exactly once

Everything in `postgres/init/` is executed by the official entrypoint **only when the data
directory is empty** — that is, on the very first start of a fresh volume. It does not re-run
on `docker compose restart`, on `up` against an existing volume, or when you edit the script.

To pick up a change to the init scripts you must discard the data:

```bash
docker compose down -v        # -v deletes the volumes — destroys the database
docker compose up --build
```

For a database that already has data, apply the change as a normal migration or `psql` command
instead. Never reach for `down -v` against anything you care about.

---

## Switching back to SQLite

Comment out the two `Database__Provider` / `ConnectionStrings__DefaultConnection` lines on the
`authserver` service and uncomment the SQLite pair directly beneath them. The `postgres`
service can stay up; nothing will connect to it.

Note that the two databases hold entirely separate data. Switching providers does not migrate
anything across — a user created under SQLite does not exist in Postgres.

---

## Data you must not lose

| Volume | Holds | If you delete it |
|---|---|---|
| `postgres-data` | Users, clients, tenants, tokens | Everything is gone |
| `auth-data` | Data-protection keys | Every issued token and cookie is invalidated |

`auth-data` matters even on Postgres. The data-protection keyring is stored on the filesystem
(`DataProtection:KeyPath`), not in the database, and OpenIddict uses it for token protection.
Losing it signs everyone out and breaks in-flight authorization codes.

---

## Production notes

These carry over from the main [production checklist](../README.md):

- **Replace the ephemeral OpenIddict signing keys.** They are regenerated on every start, so
  each container restart invalidates every token that every integrated application is holding.
- **Rotate `M2M_CLIENT_SECRET`.** The seeded default is in the repository.
- **Terminate TLS in front of the auth server.** The runtime image serves plain HTTP on 8080 by
  design; put a reverse proxy in front and set `AUTH_BASE_URI` to the public HTTPS URL.
- **Back up `postgres-data`.** `docker compose down -v` is one keystroke away from `down`.

---

## Verified

The image and role setup were exercised directly (`docker build` + `docker run`, no Compose):

- container reaches `healthy` in ~6s via the `pg_isready` health check
- the init script creates the app role correctly even when the password contains `'` and `"`
  — values are passed as psql variables, so they cannot break out into SQL
- the app role can create and drop tables in its own schema, **cannot** create roles, and
  **cannot** connect to the `postgres` maintenance database
- the auth server, pointed at this container as the app role, applied all migrations and
  created 18 tables, seeded the admin user and OIDC clients, and issued a working access token

The `docker-compose.yml` itself is valid YAML with the expected services, volumes and health
dependency, but was **not** run end to end — no Compose plugin is installed in this environment.
Expect to shake out environment-specific issues on your first `docker compose up`.
