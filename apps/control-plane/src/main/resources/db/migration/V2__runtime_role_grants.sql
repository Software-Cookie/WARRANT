-- In Google Cloud the schema is owned by the migration identity (Cloud Run job warrant-migrate) and the control
-- plane connects as a different Cloud SQL IAM user that may only assume warrant_app. Superusers (local development
-- and tests) are members of every role already, so nothing is granted to them.
DO $$
DECLARE
    runtime_user text := '${runtime_user}';
BEGIN
    IF NOT pg_has_role(current_user, 'warrant_app', 'MEMBER') THEN
        EXECUTE format('GRANT warrant_app TO %I', current_user);
    END IF;
    IF runtime_user <> '' THEN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = runtime_user) THEN
            RAISE EXCEPTION 'runtime database user % does not exist; create the Cloud SQL IAM user first', runtime_user;
        END IF;
        IF NOT pg_has_role(runtime_user, 'warrant_app', 'MEMBER') THEN
            EXECUTE format('GRANT warrant_app TO %I', runtime_user);
        END IF;
    END IF;
END
$$;
