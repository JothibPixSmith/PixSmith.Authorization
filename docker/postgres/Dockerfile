# ── PostgreSQL for PixSmith Authorization ────────────────────────────────────
#
# A thin layer over the official image. The only thing baked in is the
# initialisation script that creates a least-privilege application role — no
# credentials, no data, nothing environment-specific, so the same image is safe
# to promote from dev to production.
#
# Alpine keeps the image small; switch to `postgres:17` (Debian) if you need a
# locale or extension that is not available in the Alpine build.

FROM postgres:17-alpine

# Scripts in this directory are executed by the official entrypoint exactly once,
# on first startup, when the data directory is empty. They do NOT run again on a
# container restart or against an existing volume — see docker/README.md for what
# to do when you change them.
COPY init/ /docker-entrypoint-initdb.d/

# The entrypoint runs initdb as this user; declaring it explicitly means the
# server never runs as root even if the base image default changes.
USER postgres

# Fail the container's health check until the server is genuinely accepting
# connections, so dependents can wait on it rather than racing startup.
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=5 \
    CMD pg_isready --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" --quiet || exit 1

EXPOSE 5432
