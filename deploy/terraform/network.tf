# Private network: Cloud SQL and Memorystore have no public address. Cloud Run services reach them through Direct
# VPC egress; outbound internet (Google sign-in, external target systems) leaves through Cloud NAT.

resource "google_compute_network" "warrant" {
  name                    = "warrant"
  auto_create_subnetworks = false
  depends_on              = [google_project_service.enabled]
}

resource "google_compute_subnetwork" "run" {
  name                     = "warrant-run"
  region                   = var.region
  network                  = google_compute_network.warrant.id
  ip_cidr_range            = "10.20.0.0/22"
  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
  }
}

resource "google_compute_global_address" "private_services" {
  name          = "warrant-private-services"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 20
  network       = google_compute_network.warrant.id
}

resource "google_service_networking_connection" "private_services" {
  network                 = google_compute_network.warrant.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_services.name]
}

resource "google_compute_router" "warrant" {
  name    = "warrant"
  region  = var.region
  network = google_compute_network.warrant.id
}

resource "google_compute_router_nat" "warrant" {
  name                               = "warrant"
  router                             = google_compute_router.warrant.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

resource "google_compute_firewall" "deny_ingress_default" {
  name      = "warrant-deny-all-ingress"
  network   = google_compute_network.warrant.id
  direction = "INGRESS"
  priority  = 65000

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
}
