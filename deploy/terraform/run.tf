# Cloud Run services. Every service:
#   * runs as its own service account, from an immutable image tag;
#   * reaches Cloud SQL / Memorystore / the other services only through Direct VPC egress;
#   * accepts traffic only from the VPC or the HTTPS load balancer (never directly from the internet).

locals {
  cp_internal_url = "https://warrant-control-plane-${data.google_project.this.number}.${var.region}.run.app"
  classifier_url  = "https://warrant-classifier-${data.google_project.this.number}.${var.region}.run.app"
  redis_env = {
    WARRANT_REDIS_HOST                                       = google_redis_instance.warrant.host
    WARRANT_REDIS_PORT                                       = tostring(google_redis_instance.warrant.port)
    WARRANT_REDIS_TLS                                        = "true"
    SPRING_DATA_REDIS_SSL_BUNDLE                             = "memorystore"
    SPRING_SSL_BUNDLE_PEM_MEMORYSTORE_TRUSTSTORE_CERTIFICATE = "file:/etc/warrant/redis-ca/ca.pem"
  }
  db_env = {
    WARRANT_DB_INSTANCE = google_sql_database_instance.warrant.connection_name
    WARRANT_DB_NAME     = google_sql_database.warrant.name
  }
}

data "google_project" "this" {}

# ------------------------------------------------------------------------------------------------ migration job

resource "google_cloud_run_v2_job" "migrate" {
  name                = "warrant-migrate"
  location            = var.region
  deletion_protection = false

  template {
    template {
      service_account = google_service_account.migrate.email
      timeout         = "600s"
      max_retries     = 1

      containers {
        image = local.images.control_plane
        dynamic "env" {
          for_each = merge(local.db_env, local.redis_env, {
            WARRANT_ENV                      = var.env
            WARRANT_REGION                   = var.region
            WARRANT_DB_IAM_USER              = google_sql_user.migrate.name
            WARRANT_DB_RUNTIME_USER          = google_sql_user.control_plane.name
            WARRANT_DB_MIGRATE               = "true"
            WARRANT_MIGRATE_ONLY             = "true"
            WARRANT_PROVISION_FILE           = "/etc/warrant/provision/provision.json"
            WARRANT_OIDC_AUDIENCE            = var.oidc_client_id
            WARRANT_KMS_ENVELOPE_KEY         = google_kms_crypto_key.envelope.id
            WARRANT_CONTROL_PLANE_URL        = local.cp_internal_url
            WARRANT_PEP_SERVICE_ACCOUNT      = google_service_account.pep.email
            SPRING_MAIN_WEB_APPLICATION_TYPE = "none"
          })
          content {
            name  = env.key
            value = env.value
          }
        }
        env {
          name = "SPRING_DATA_REDIS_PASSWORD"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.redis_auth.secret_id
              version = "latest"
            }
          }
        }
        volume_mounts {
          name       = "redis-ca"
          mount_path = "/etc/warrant/redis-ca"
        }
        volume_mounts {
          name       = "provision"
          mount_path = "/etc/warrant/provision"
        }
        resources {
          limits = { cpu = "1", memory = "1Gi" }
        }
      }

      volumes {
        name = "redis-ca"
        secret {
          secret = google_secret_manager_secret.redis_ca.secret_id
          items {
            version = "latest"
            path    = "ca.pem"
          }
        }
      }
      volumes {
        name = "provision"
        secret {
          secret = google_secret_manager_secret.provision.secret_id
          items {
            version = "latest"
            path    = "provision.json"
          }
        }
      }

      vpc_access {
        egress = "PRIVATE_RANGES_ONLY"
        network_interfaces {
          network    = google_compute_network.warrant.id
          subnetwork = google_compute_subnetwork.run.id
        }
      }
    }
  }

  # Targeting this job (terraform apply -target=google_cloud_run_v2_job.migrate) brings up everything the first
  # migration needs, including the grants below, before any long-running service exists.
  depends_on = [
    google_secret_manager_secret_version.redis_auth,
    google_secret_manager_secret_version.redis_ca,
    google_secret_manager_secret_iam_member.redis_readers,
    google_secret_manager_secret_iam_member.migrate_reads_provision,
    google_project_iam_member.sql_client,
    google_project_iam_member.sql_instance_user,
    google_project_iam_member.telemetry,
  ]
}

# ---------------------------------------------------------------------------------------------- control plane

resource "google_cloud_run_v2_service" "control_plane" {
  name                = "warrant-control-plane"
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  deletion_protection = true
  labels              = local.labels

  template {
    service_account                  = google_service_account.control_plane.email
    max_instance_request_concurrency = 200
    timeout                          = "300s"

    scaling {
      min_instance_count = 1
      max_instance_count = 20
    }

    containers {
      image = local.images.control_plane
      ports {
        container_port = 8081
      }
      dynamic "env" {
        for_each = merge(local.db_env, local.redis_env, {
          WARRANT_ENV                 = var.env
          WARRANT_REGION              = var.region
          WARRANT_DB_IAM_USER         = google_sql_user.control_plane.name
          WARRANT_DB_MIGRATE          = "false"
          WARRANT_CONTROL_PLANE_URL   = local.cp_internal_url
          WARRANT_PEP_SERVICE_ACCOUNT = google_service_account.pep.email
          WARRANT_OIDC_AUDIENCE       = var.oidc_client_id
          WARRANT_KMS_ENVELOPE_KEY    = google_kms_crypto_key.envelope.id
          WARRANT_CONSOLE_URL         = "https://console.${var.domain}"
        })
        content {
          name  = env.key
          value = env.value
        }
      }
      env {
        name = "SPRING_DATA_REDIS_PASSWORD"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.redis_auth.secret_id
            version = "latest"
          }
        }
      }
      volume_mounts {
        name       = "redis-ca"
        mount_path = "/etc/warrant/redis-ca"
      }
      resources {
        limits            = { cpu = "2", memory = "2Gi" }
        cpu_idle          = false
        startup_cpu_boost = true
      }
      startup_probe {
        http_get {
          path = "/actuator/health/readiness"
          port = 8081
        }
        period_seconds    = 5
        failure_threshold = 24
      }
      liveness_probe {
        http_get {
          path = "/actuator/health/liveness"
          port = 8081
        }
        period_seconds = 15
      }
    }

    volumes {
      name = "redis-ca"
      secret {
        secret = google_secret_manager_secret.redis_ca.secret_id
        items {
          version = "latest"
          path    = "ca.pem"
        }
      }
    }

    vpc_access {
      egress = "PRIVATE_RANGES_ONLY"
      network_interfaces {
        network    = google_compute_network.warrant.id
        subnetwork = google_compute_subnetwork.run.id
      }
    }
  }

  depends_on = [
    google_cloud_run_v2_job.migrate,
    google_secret_manager_secret_iam_member.redis_readers,
    google_kms_crypto_key_iam_member.cp_envelope,
    google_kms_crypto_key_iam_member.cp_signs_warrants,
    google_kms_crypto_key_iam_member.cp_signs_audit_heads,
    google_project_iam_member.sql_client,
    google_project_iam_member.sql_instance_user,
  ]
}

# ------------------------------------------------------------------------------------------------- classifier

resource "google_cloud_run_v2_service" "classifier" {
  name                = "warrant-classifier"
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  deletion_protection = true
  labels              = local.labels

  template {
    service_account                  = google_service_account.classifier.email
    max_instance_request_concurrency = 64

    scaling {
      min_instance_count = 1
      max_instance_count = 30
    }

    containers {
      image = local.images.classifier
      ports {
        container_port = 8090
      }
      env {
        name  = "WARRANT_CLASSIFIER_BACKEND"
        value = var.classifier_backend
      }
      env {
        name  = "WARRANT_GEMMA_ENDPOINT"
        value = var.gemma_endpoint
      }
      env {
        name  = "WARRANT_CARD_BACKEND"
        value = "gemini"
      }
      env {
        name  = "WARRANT_GEMINI_PROJECT"
        value = var.project_id
      }
      env {
        name  = "WARRANT_GEMINI_LOCATION"
        value = var.region
      }
      resources {
        limits = { cpu = "2", memory = "1Gi" }
      }
      startup_probe {
        http_get {
          path = "/health"
          port = 8090
        }
      }
    }

    vpc_access {
      egress = "PRIVATE_RANGES_ONLY"
      network_interfaces {
        network    = google_compute_network.warrant.id
        subnetwork = google_compute_subnetwork.run.id
      }
    }
  }
}

# Only the gateway may call the classifier (Cloud Run verifies the gateway's Google ID token).
resource "google_cloud_run_v2_service_iam_member" "pep_invokes_classifier" {
  name     = google_cloud_run_v2_service.classifier.name
  location = var.region
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.pep.email}"
}

# --------------------------------------------------------------------------------------------------- gateway

resource "google_cloud_run_v2_service" "pep" {
  name                = "warrant-pep-gateway"
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  deletion_protection = true
  labels              = local.labels

  template {
    service_account                  = google_service_account.pep.email
    max_instance_request_concurrency = 250
    timeout                          = "120s"

    scaling {
      min_instance_count = var.pep_min_instances
      max_instance_count = 50
    }

    containers {
      image = local.images.pep_gateway
      ports {
        container_port = 8080
      }
      dynamic "env" {
        for_each = merge(local.redis_env, {
          WARRANT_ENV                         = var.env
          WARRANT_REGION                      = var.region
          WARRANT_PEP_TENANTS                 = join(",", var.tenants)
          WARRANT_CONTROL_PLANE_URL           = local.cp_internal_url
          WARRANT_CLASSIFIER_URL              = local.classifier_url
          WARRANT_CLASSIFIER_CONFIDENCE_FLOOR = "0.6"
        })
        content {
          name  = env.key
          value = env.value
        }
      }
      env {
        name = "SPRING_DATA_REDIS_PASSWORD"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.redis_auth.secret_id
            version = "latest"
          }
        }
      }
      volume_mounts {
        name       = "redis-ca"
        mount_path = "/etc/warrant/redis-ca"
      }
      resources {
        limits            = { cpu = "2", memory = "1Gi" }
        cpu_idle          = false
        startup_cpu_boost = true
      }
      startup_probe {
        http_get {
          path = "/actuator/health/readiness"
          port = 8080
        }
        period_seconds    = 3
        failure_threshold = 30
      }
      liveness_probe {
        http_get {
          path = "/actuator/health/liveness"
          port = 8080
        }
      }
    }

    volumes {
      name = "redis-ca"
      secret {
        secret = google_secret_manager_secret.redis_ca.secret_id
        items {
          version = "latest"
          path    = "ca.pem"
        }
      }
    }

    # ALL_TRAFFIC: calls to the control plane and classifier must arrive from the VPC to pass their ingress rules;
    # target systems on the internet are reached through Cloud NAT with a stable egress address.
    vpc_access {
      egress = "ALL_TRAFFIC"
      network_interfaces {
        network    = google_compute_network.warrant.id
        subnetwork = google_compute_subnetwork.run.id
      }
    }
  }

  depends_on = [google_secret_manager_secret_iam_member.pep_reads_targets]
}

# ---------------------------------------------------------------------------------------------------- console

resource "google_cloud_run_v2_service" "console" {
  name                = "warrant-console"
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  deletion_protection = true
  labels              = local.labels

  template {
    service_account = google_service_account.console.email

    scaling {
      min_instance_count = 1
      max_instance_count = 10
    }

    containers {
      image = local.images.console
      ports {
        container_port = 3000
      }
      env {
        name  = "WARRANT_ENV"
        value = var.env
      }
      env {
        name  = "WARRANT_CONTROL_PLANE_URL"
        value = local.cp_internal_url
      }
      env {
        name  = "WARRANT_CONSOLE_URL"
        value = "https://console.${var.domain}"
      }
      env {
        name  = "WARRANT_OIDC_CLIENT_ID"
        value = var.oidc_client_id
      }
      env {
        name  = "WARRANT_DEFAULT_TENANT"
        value = var.tenants[0]
      }
      env {
        name = "WARRANT_OIDC_CLIENT_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.oidc_client_secret.secret_id
            version = "latest"
          }
        }
      }
      resources {
        limits = { cpu = "1", memory = "512Mi" }
      }
    }

    vpc_access {
      egress = "ALL_TRAFFIC"
      network_interfaces {
        network    = google_compute_network.warrant.id
        subnetwork = google_compute_subnetwork.run.id
      }
    }
  }

  depends_on = [google_secret_manager_secret_iam_member.console_reads_oidc]
}

# Console, control plane and gateway authenticate every request themselves (OIDC sessions, warrants with proof of
# possession, Google ID tokens for internal routes), and their ingress admits only the load balancer and the VPC.
resource "google_cloud_run_v2_service_iam_member" "public_behind_lb" {
  for_each = {
    console       = google_cloud_run_v2_service.console.name
    control_plane = google_cloud_run_v2_service.control_plane.name
    pep           = google_cloud_run_v2_service.pep.name
  }
  name     = each.value
  location = var.region
  role     = "roles/run.invoker"
  member   = "allUsers"
}
