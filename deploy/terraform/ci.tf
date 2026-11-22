# Keyless CI: GitHub Actions exchanges its OIDC token for short-lived Google credentials. No JSON key exists.

resource "google_service_account" "deployer" {
  count        = var.github_repository == "" ? 0 : 1
  account_id   = "warrant-deployer"
  display_name = "Warrant CI deployer (GitHub Actions via Workload Identity Federation)"
}

resource "google_iam_workload_identity_pool" "github" {
  count                     = var.github_repository == "" ? 0 : 1
  workload_identity_pool_id = "github"
  display_name              = "GitHub Actions"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  count                              = var.github_repository == "" ? 0 : 1
  workload_identity_pool_id          = google_iam_workload_identity_pool.github[0].workload_identity_pool_id
  workload_identity_pool_provider_id = "github"
  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
    "attribute.ref"        = "assertion.ref"
  }
  attribute_condition = "assertion.repository == '${var.github_repository}' && assertion.ref == 'refs/heads/main'"
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account_iam_member" "github_impersonates_deployer" {
  count              = var.github_repository == "" ? 0 : 1
  service_account_id = google_service_account.deployer[0].name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github[0].name}/attribute.repository/${var.github_repository}"
}

resource "google_artifact_registry_repository_iam_member" "deployer_pushes" {
  count      = var.github_repository == "" ? 0 : 1
  location   = var.region
  repository = google_artifact_registry_repository.warrant.repository_id
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.deployer[0].email}"
}

resource "google_project_iam_member" "deployer_runs" {
  count   = var.github_repository == "" ? 0 : 1
  project = var.project_id
  role    = "roles/run.developer"
  member  = "serviceAccount:${google_service_account.deployer[0].email}"
}

# run.developer may deploy a revision that runs as these accounts, and nothing else.
resource "google_service_account_iam_member" "deployer_acts_as" {
  for_each           = var.github_repository == "" ? {} : local.workloads
  service_account_id = "projects/${var.project_id}/serviceAccounts/${each.value}"
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.deployer[0].email}"
}
