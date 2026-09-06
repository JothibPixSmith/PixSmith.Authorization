#!/bin/bash
#
# Creates the least-privilege role the auth server connects as.
#
# The superuser created by POSTGRES_USER is for administration only. The
# application gets its own role that can read and write its own schema and
# nothing else — so a compromised connection string cannot read other databases
# on the same server, create roles, or write to disk via COPY TO PROGRAM.
#
# Runs once, on first initialisation of an empty data directory.

set -euo pipefail

if [ -z "${APP_DB_USER:-}" ] || [ -z "${APP_DB_PASSWORD:-}" ]; then
    echo "init: APP_DB_USER/APP_DB_PASSWORD not set — skipping application role creation."
    echo "init: the auth server will have to connect as the superuser, which is not recommended."
    exit 0
fi

# Values are passed as psql variables and interpolated with :'...' (literal) and
# :"..." (identifier) so a password containing quotes cannot terminate the string
# and inject SQL.
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     --no-password --set ON_ERROR_STOP=1 \
     --set app_user="$APP_DB_USER" \
     --set app_password="$APP_DB_PASSWORD" \
     --set db_name="$POSTGRES_DB" <<-'EOSQL'

    CREATE ROLE :"app_user" WITH LOGIN PASSWORD :'app_password';

    -- PostgreSQL grants CONNECT on every database to PUBLIC by default, so
    -- without these revokes the application role could open a session against
    -- the maintenance databases. Superusers bypass these checks, so
    -- administration is unaffected.
    REVOKE CONNECT ON DATABASE postgres    FROM PUBLIC;
    REVOKE CONNECT ON DATABASE template1   FROM PUBLIC;
    REVOKE CONNECT ON DATABASE :"db_name"  FROM PUBLIC;

    GRANT CONNECT ON DATABASE :"db_name" TO :"app_user";

    -- EF Core migrations run on application startup and need to create tables,
    -- so the app role owns the schema it lives in. It still holds no privileges
    -- on any other database, and is not a superuser.
    ALTER SCHEMA public OWNER TO :"app_user";

    -- PostgreSQL 15+ already revokes this, but be explicit: no other role gets
    -- to create objects in the application's schema.
    REVOKE CREATE ON SCHEMA public FROM PUBLIC;

EOSQL

echo "init: created application role '$APP_DB_USER' owning schema public in '$POSTGRES_DB'."
