variable "project_id" {
  description = "Google Cloud project that hosts Warrant."
  type        = string
}

variable "region" {
  description = "Region for every regional resource. Data stays in this region."
  type        = string
  default     = "asia-south1"
}

variable "env" {
  description = "Environment name, passed to the services as WARRANT_ENV. Must not be local, demo or test."
  type        = string
  default     = "prod"
  validation {
    condition     = !contains(["local", "demo", "test"], var.env)
    error_message = "Development environment names enable development-only code paths and are refused here."
  }
}

variable "image_tag" {
  description = "Immutable image tag (the git commit SHA) deployed to every service."
  type        = string
}

variable "domain" {
  description = "Base DNS name. Creates console.<domain>, api.<domain> and pep.<domain> behind the HTTPS load balancer."
  type        = string
}

variable "tenants" {
  description = "Tenant ids. Each gets its own Cloud KMS warrant-signing and audit-signing keys."
  type        = list(string)
  default     = ["acme"]
}

variable "oidc_client_id" {
  description = "OAuth 2.0 web client id used by the console for Google sign-in (also the control plane's token audience)."
  type        = string
}

variable "kms_protection_level" {
  description = "HSM keeps signing keys in FIPS 140-2 Level 3 hardware. SOFTWARE is cheaper for non-production."
  type        = string
  default     = "HSM"
}

variable "db_tier" {
  description = "Cloud SQL machine tier."
  type        = string
  default     = "db-custom-2-7680"
}

variable "redis_memory_gb" {
  description = "Memorystore capacity."
  type        = number
  default     = 2
}

variable "classifier_backend" {
  description = "heuristic (deterministic, no model) or gemma (self-hosted endpoint from deploy/k8s)."
  type        = string
  default     = "heuristic"
}

variable "gemma_endpoint" {
  description = "Internal URL of the Gemma serving endpoint when classifier_backend = gemma."
  type        = string
  default     = ""
}

variable "github_repository" {
  description = "owner/repo allowed to deploy through Workload Identity Federation. Empty disables CI federation."
  type        = string
  default     = ""
}

variable "pep_min_instances" {
  description = "Warm gateway instances. The gateway is on the hot path of every agent call."
  type        = number
  default     = 2
}
