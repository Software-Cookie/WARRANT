# --------------------------------------------------------------------------------------------- Cloud SQL (Postgres)

resource "google_sql_database_instance" "warrant" {
  name                = "warrant-pg"
  region              = var.region
  database_version    = "POSTGRES_16"
  deletion_protection = true
  depends_on          = [google_service_networking_connection.private_services]

  settings {
    tier              = var.db_tier
    edition           = "ENTERPRISE"
    availability_type = "REGIONAL"
    disk_type         = "PD_SSD"
    disk_autoresize   = true
    user_labels       = local.labels

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.warrant.id
      ssl_mode        = "ENCRYPTED_ONLY"
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "20:30"
      transaction_log_retention_days = 7
      backup_retention_settings {
        retained_backups = 30
      }
    }

    database_flags {
      name  = "cloudsql.iam_authentication"
      value = "on"
    }
    database_flags {
      name  = "log_min_duration_statement"
      value = "500"
    }
    database_flags {
      name  = "log_connections"
      value = "on"
    }

    insights_config {
      query_insights_enabled  = true
      record_application_tags = true
    }

    maintenance_window {
      day  = 7
      hour = 21
    }
  }
}

resource "google_sql_database" "warrant" {
  name     = "warrant"
  instance = google_sql_database_instance.warrant.name
}

# Cloud SQL IAM users: the database user name is the service account email without ".gserviceaccount.com".
resource "google_sql_user" "migrate" {
  name     = trimsuffix(google_service_account.migrate.email, ".gserviceaccount.com")
  instance = google_sql_database_instance.warrant.name
  type     = "CLOUD_IAM_SERVICE_ACCOUNT"
}

resource "google_sql_user" "control_plane" {
  name     = trimsuffix(google_service_account.control_plane.email, ".gserviceaccount.com")
  instance = google_sql_database_instance.warrant.name
  type     = "CLOUD_IAM_SERVICE_ACCOUNT"
}

# ------------------------------------------------------------------------------------------ Memorystore (Redis)

resource "google_redis_instance" "warrant" {
  name                    = "warrant"
  region                  = var.region
  tier                    = "STANDARD_HA"
  memory_size_gb          = var.redis_memory_gb
  redis_version           = "REDIS_7_2"
  authorized_network      = google_compute_network.warrant.id
  connect_mode            = "PRIVATE_SERVICE_ACCESS"
  auth_enabled            = true
  transit_encryption_mode = "SERVER_AUTHENTICATION"
  labels                  = local.labels
  depends_on              = [google_service_networking_connection.private_services]

  maintenance_policy {
    weekly_maintenance_window {
      day = "SUNDAY"
      start_time {
        hours   = 21
        minutes = 0
      }
    }
  }
}
