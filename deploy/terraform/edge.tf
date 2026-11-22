# Global external HTTPS load balancer with Cloud Armor in front of console, API and gateway.
#   console.<domain>  -> console
#   api.<domain>      -> control plane (public /v1 API; /internal is blocked at the edge)
#   pep.<domain>      -> gateway (agents running outside Google Cloud)

locals {
  hosts = {
    console = { host = "console.${var.domain}", service = google_cloud_run_v2_service.console.name }
    api     = { host = "api.${var.domain}", service = google_cloud_run_v2_service.control_plane.name }
    pep     = { host = "pep.${var.domain}", service = google_cloud_run_v2_service.pep.name }
  }
}

resource "google_compute_global_address" "edge" {
  name = "warrant-edge"
}

resource "google_compute_region_network_endpoint_group" "run" {
  for_each              = local.hosts
  name                  = "warrant-${each.key}"
  region                = var.region
  network_endpoint_type = "SERVERLESS"
  cloud_run {
    service = each.value.service
  }
}

resource "google_compute_security_policy" "edge" {
  name = "warrant-edge"

  rule {
    action      = "deny(404)"
    priority    = 100
    description = "Internal control-plane routes are never reachable from the internet"
    match {
      expr {
        expression = "request.path.startsWith('/internal')"
      }
    }
  }

  rule {
    action      = "deny(403)"
    priority    = 200
    description = "OWASP CRS: SQLi, XSS, LFI, RCE, protocol attacks (console and API only; the gateway carries SQL by design)"
    match {
      expr {
        expression = "!request.headers['host'].startsWith('pep.') && (evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 1}) || evaluatePreconfiguredWaf('xss-v33-stable', {'sensitivity': 1}) || evaluatePreconfiguredWaf('lfi-v33-stable', {'sensitivity': 1}) || evaluatePreconfiguredWaf('rce-v33-stable', {'sensitivity': 1}) || evaluatePreconfiguredWaf('protocolattack-v33-stable', {'sensitivity': 1}))"
      }
    }
  }

  rule {
    action      = "throttle"
    priority    = 1000
    description = "Per-client rate limit at the edge; the gateway also limits per agent and per tenant"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"
      rate_limit_threshold {
        count        = 1200
        interval_sec = 60
      }
    }
  }

  rule {
    action   = "allow"
    priority = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
  }

  advanced_options_config {
    log_level = "VERBOSE"
  }
}

resource "google_compute_backend_service" "run" {
  for_each              = local.hosts
  name                  = "warrant-${each.key}"
  protocol              = "HTTPS"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  security_policy       = google_compute_security_policy.edge.id

  backend {
    group = google_compute_region_network_endpoint_group.run[each.key].id
  }

  log_config {
    enable      = true
    sample_rate = 1.0
  }
}

resource "google_compute_url_map" "edge" {
  name            = "warrant-edge"
  default_service = google_compute_backend_service.run["console"].id

  dynamic "host_rule" {
    for_each = local.hosts
    content {
      hosts        = [host_rule.value.host]
      path_matcher = host_rule.key
    }
  }

  dynamic "path_matcher" {
    for_each = local.hosts
    content {
      name            = path_matcher.key
      default_service = google_compute_backend_service.run[path_matcher.key].id
    }
  }
}

resource "google_compute_managed_ssl_certificate" "edge" {
  name = "warrant-edge"
  managed {
    domains = [for h in local.hosts : h.host]
  }
}

resource "google_compute_ssl_policy" "modern" {
  name            = "warrant-modern-tls"
  profile         = "MODERN"
  min_tls_version = "TLS_1_2"
}

resource "google_compute_target_https_proxy" "edge" {
  name             = "warrant-edge"
  url_map          = google_compute_url_map.edge.id
  ssl_certificates = [google_compute_managed_ssl_certificate.edge.id]
  ssl_policy       = google_compute_ssl_policy.modern.id
}

resource "google_compute_global_forwarding_rule" "https" {
  name                  = "warrant-https"
  target                = google_compute_target_https_proxy.edge.id
  port_range            = "443"
  ip_address            = google_compute_global_address.edge.id
  load_balancing_scheme = "EXTERNAL_MANAGED"
}

resource "google_compute_url_map" "redirect" {
  name = "warrant-http-redirect"
  default_url_redirect {
    https_redirect         = true
    strip_query            = false
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
  }
}

resource "google_compute_target_http_proxy" "redirect" {
  name    = "warrant-http-redirect"
  url_map = google_compute_url_map.redirect.id
}

resource "google_compute_global_forwarding_rule" "http" {
  name                  = "warrant-http"
  target                = google_compute_target_http_proxy.redirect.id
  port_range            = "80"
  ip_address            = google_compute_global_address.edge.id
  load_balancing_scheme = "EXTERNAL_MANAGED"
}
