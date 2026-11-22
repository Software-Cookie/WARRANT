# ADR 0004: The schema owner is not the runtime identity

Status: accepted

## Context
Locally the control plane migrates its own schema as a superuser. In production that would let a compromised control
plane alter the tables it writes, including the audit table's triggers.

## Decision
A Cloud Run job, `warrant-migrate`, runs the control-plane image with `WARRANT_MIGRATE_ONLY=true` under its own
service account. It owns the schema, applies Flyway migrations, provisions tenants from `WARRANT_PROVISION_FILE`, and
exits. Migration V2 grants the runtime IAM user membership in `warrant_app` only. The control plane runs with
`WARRANT_DB_MIGRATE=false`.

## Consequences
One extra deploy step (run the job before rolling out). The one-time database bootstrap
(`deploy/terraform/sql/bootstrap.sql`) is the only operation that uses the built-in `postgres` user.
