#!/bin/sh
# Runs once, on first start of the local Postgres container. Local development uses trust authentication on a
# private Docker network that publishes no port; Cloud SQL in Google Cloud uses IAM authentication only.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<'SQL'
CREATE DATABASE warrant;
CREATE DATABASE acme;
SQL
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname acme -f /demo/acme/schema.sql
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname acme -c "SELECT * FROM acme_reset();"
