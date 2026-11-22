output "edge_ip" {
  description = "Create A records for console., api. and pep.<domain> pointing here."
  value       = google_compute_global_address.edge.address
}

output "artifact_registry" {
  value = local.registry
}

output "control_plane_internal_url" {
  value = local.cp_internal_url
}

output "kms_key_versions" {
  description = "Key version names for the provisioning file (version 1 of each key)."
  value = {
    for t in var.tenants : t => {
      kms_key_version       = "${google_kms_crypto_key.warrant_signing[t].id}/cryptoKeyVersions/1"
      kms_audit_key_version = "${google_kms_crypto_key.audit_signing[t].id}/cryptoKeyVersions/1"
    }
  }
}

output "target_credential_secrets" {
  description = "Use as credential_ref: gcp-secret://<name>/versions/latest"
  value       = { for k, s in google_secret_manager_secret.target : k => s.id }
}

output "workload_identity_provider" {
  value = var.github_repository == "" ? null : google_iam_workload_identity_pool_provider.github[0].name
}

output "deployer_service_account" {
  value = var.github_repository == "" ? null : google_service_account.deployer[0].email
}
