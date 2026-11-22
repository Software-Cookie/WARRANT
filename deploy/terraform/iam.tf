# One service account per workload, each with only what it uses.

resource "google_service_account" "control_plane" {
  account_id   = "warrant-cp"
  display_name = "Warrant control plane (runtime)"
}

resource "google_service_account" "migrate" {
  account_id   = "warrant-migrate"
  display_name = "Warrant schema migrations and tenant provisioning (Cloud Run job)"
}

resource "google_service_account" "pep" {
  account_id   = "warrant-pep"
  display_name = "Warrant policy enforcement gateway"
}

resource "google_service_account" "classifier" {
  account_id   = "warrant-classifier"
  display_name = "Warrant classifier"
}

resource "google_service_account" "console" {
  account_id   = "warrant-console"
  display_name = "Warrant console"
}

locals {
  telemetry_roles = ["roles/logging.logWriter", "roles/monitoring.metricWriter", "roles/cloudtrace.agent"]
  workloads = {
    control_plane = google_service_account.control_plane.email
    migrate       = google_service_account.migrate.email
    pep           = google_service_account.pep.email
    classifier    = google_service_account.classifier.email
    console       = google_service_account.console.email
  }
  telemetry_bindings = merge([
    for workload, email in local.workloads : {
      for role in local.telemetry_roles : "${workload}/${role}" => { email = email, role = role }
    }
  ]...)
}

resource "google_project_iam_member" "telemetry" {
  for_each = local.telemetry_bindings
  project  = var.project_id
  role     = each.value.role
  member   = "serviceAccount:${each.value.email}"
}

# Cloud SQL: connect with IAM database authentication (no password).
resource "google_project_iam_member" "sql_client" {
  for_each = toset([google_service_account.control_plane.email, google_service_account.migrate.email])
  project  = var.project_id
  role     = "roles/cloudsql.client"
  member   = "serviceAccount:${each.value}"
}

resource "google_project_iam_member" "sql_instance_user" {
  for_each = toset([google_service_account.control_plane.email, google_service_account.migrate.email])
  project  = var.project_id
  role     = "roles/cloudsql.instanceUser"
  member   = "serviceAccount:${each.value}"
}

# The classifier may call Gemini on Vertex AI for approval-card wording (metadata and counts only).
resource "google_project_iam_member" "classifier_vertex" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.classifier.email}"
}
