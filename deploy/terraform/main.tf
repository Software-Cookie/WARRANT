locals {
  services = [
    "run.googleapis.com",
    "sqladmin.googleapis.com",
    "redis.googleapis.com",
    "cloudkms.googleapis.com",
    "secretmanager.googleapis.com",
    "artifactregistry.googleapis.com",
    "servicenetworking.googleapis.com",
    "compute.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "cloudtrace.googleapis.com",
    "aiplatform.googleapis.com",
    "containerscanning.googleapis.com",
    "certificatemanager.googleapis.com",
  ]
  registry = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.warrant.repository_id}"
  images = {
    control_plane = "${local.registry}/control-plane:${var.image_tag}"
    pep_gateway   = "${local.registry}/pep-gateway:${var.image_tag}"
    classifier    = "${local.registry}/classifier:${var.image_tag}"
    console       = "${local.registry}/console:${var.image_tag}"
  }
  labels = { app = "warrant", env = var.env }
}

resource "google_project_service" "enabled" {
  for_each           = toset(local.services)
  service            = each.value
  disable_on_destroy = false
}

resource "google_artifact_registry_repository" "warrant" {
  location      = var.region
  repository_id = "warrant"
  format        = "DOCKER"
  description   = "Warrant service images. Tags are immutable commit SHAs."
  labels        = local.labels

  docker_config {
    immutable_tags = true
  }

  cleanup_policies {
    id     = "keep-recent"
    action = "KEEP"
    most_recent_versions {
      keep_count = 30
    }
  }

  depends_on = [google_project_service.enabled]
}
