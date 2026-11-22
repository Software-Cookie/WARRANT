# Runbook: deploy to Google Cloud

The full procedure is in **Warrant_GCP_Deployment_Guide.pdf** (next to the project documents). Short form:

1. Project, billing, `gcloud auth login`, a versioned state bucket.
2. OAuth consent screen and a Web OAuth client (redirect `https://console.<domain>/api/auth/google/callback`).
3. `terraform init -backend-config=bucket=<state-bucket>` then `terraform apply` with `terraform.tfvars`.
4. Point `console.`, `api.` and `pep.<domain>` at the `edge_ip` output; wait for the managed certificate.
5. Add secret values: OAuth client secret, each target credential, the provisioning file (KMS key versions from the
   `kms_key_versions` output).
6. In Cloud SQL Studio, as `postgres`, run `deploy/terraform/sql/bootstrap.sql` once.
7. Build and push images tagged with the commit SHA; `gcloud run jobs execute warrant-migrate --wait`; deploy services.
8. Sign in to the console as the provisioned owner; register tools (`credential_ref: gcp-secret://...`) and agents,
   publish the policy, then `warrant audit verify`.
