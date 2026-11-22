-- One-time database bootstrap. Run in Cloud SQL Studio, database "warrant", as the built-in "postgres" user, after
-- the warrant-migrate job and its Cloud SQL IAM users exist. Replace PROJECT_ID (2 identities below).
--
-- Afterwards nothing uses a password: reset the postgres password to a long random value you do not keep.
--
-- The migration identity owns the schema but is NOT a superuser: it may create objects in this database and
-- administer the single role warrant_app. The runtime identity only connects; migration V2 lets it assume
-- warrant_app, which has no UPDATE or DELETE on the audit table.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'warrant_app') THEN
        CREATE ROLE warrant_app NOLOGIN;
    END IF;
END
$$;
GRANT warrant_app TO "warrant-migrate@PROJECT_ID.iam" WITH ADMIN OPTION;
GRANT CONNECT, CREATE, TEMPORARY ON DATABASE warrant TO "warrant-migrate@PROJECT_ID.iam";
GRANT USAGE, CREATE ON SCHEMA public TO "warrant-migrate@PROJECT_ID.iam";
GRANT CONNECT ON DATABASE warrant TO "warrant-cp@PROJECT_ID.iam";
