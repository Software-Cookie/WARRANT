# Secret Manager holds every credential. Terraform creates the containers; values are added out of band
# (gcloud secrets versions add ... --data-file=-) so no secret value ever enters Terraform state or the repository,
# except the Memorystore AUTH string and CA, which Google generates and which therefore already live in state.

locals {
  # Target-system credentials the gateway injects at request time. Add one entry per protected system.
  target_credentials = ["acme-erp-token"]
}

resource "google_secret_manager_secret" "target" {
  for_each  = toset(local.target_credentials)
  secret_id = "warrant-target-${each.value}"
  labels    = local.labels

  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }
}

resource "google_secret_manager_secret_iam_member" "pep_reads_targets" {
  for_each  = google_secret_manager_secret.target
  secret_id = each.value.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.pep.email}"
}

resource "google_secret_manager_secret" "oidc_client_secret" {
  secret_id = "warrant-console-oidc-client-secret"
  labels    = local.labels
  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }
}

resource "google_secret_manager_secret_iam_member" "console_reads_oidc" {
  secret_id = google_secret_manager_secret.oidc_client_secret.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.console.email}"
}

resource "google_secret_manager_secret" "redis_auth" {
  secret_id = "warrant-redis-auth"
  labels    = local.labels
  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }
}

resource "google_secret_manager_secret_version" "redis_auth" {
  secret      = google_secret_manager_secret.redis_auth.id
  secret_data = google_redis_instance.warrant.auth_string
}

resource "google_secret_manager_secret" "redis_ca" {
  secret_id = "warrant-redis-ca"
  labels    = local.labels
  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }
}

resource "google_secret_manager_secret_version" "redis_ca" {
  secret      = google_secret_manager_secret.redis_ca.id
  secret_data = join("\n", [for c in google_redis_instance.warrant.server_ca_certs : c.cert])
}

resource "google_secret_manager_secret_iam_member" "redis_readers" {
  for_each = {
    for pair in setproduct(["auth", "ca"], [google_service_account.control_plane.email, google_service_account.pep.email, google_service_account.migrate.email]) :
    "${pair[0]}/${pair[1]}" => { secret = pair[0] == "auth" ? google_secret_manager_secret.redis_auth.id : google_secret_manager_secret.redis_ca.id, email = pair[1] }
  }
  secret_id = each.value.secret
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${each.value.email}"
}

# Tenant provisioning file (tenant ids, KMS key versions, first owners). Not a credential, but access-controlled.
resource "google_secret_manager_secret" "provision" {
  secret_id = "warrant-provision"
  labels    = local.labels
  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }
}

resource "google_secret_manager_secret_iam_member" "migrate_reads_provision" {
  secret_id = google_secret_manager_secret.provision.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.migrate.email}"
}
