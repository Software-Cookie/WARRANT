# Signing keys never leave Cloud KMS: the control plane calls asymmetricSign and holds only public keys.

resource "google_kms_key_ring" "warrant" {
  name       = "warrant"
  location   = var.region
  depends_on = [google_project_service.enabled]
}

resource "google_kms_crypto_key" "warrant_signing" {
  for_each = toset(var.tenants)
  name     = "${each.value}-warrant"
  key_ring = google_kms_key_ring.warrant.id
  purpose  = "ASYMMETRIC_SIGN"
  labels   = merge(local.labels, { tenant = each.value, use = "warrant" })

  version_template {
    algorithm        = "EC_SIGN_ED25519"
    protection_level = var.kms_protection_level
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "audit_signing" {
  for_each = toset(var.tenants)
  name     = "${each.value}-audit"
  key_ring = google_kms_key_ring.warrant.id
  purpose  = "ASYMMETRIC_SIGN"
  labels   = merge(local.labels, { tenant = each.value, use = "audit" })

  version_template {
    algorithm        = "EC_SIGN_ED25519"
    protection_level = var.kms_protection_level
  }

  lifecycle {
    prevent_destroy = true
  }
}

# Key-encryption key for the envelope encryption of parked tool-call arguments and release results.
resource "google_kms_crypto_key" "envelope" {
  name            = "envelope"
  key_ring        = google_kms_key_ring.warrant.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = "7776000s"
  labels          = merge(local.labels, { use = "envelope" })

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = var.kms_protection_level
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "cp_signs_warrants" {
  for_each      = google_kms_crypto_key.warrant_signing
  crypto_key_id = each.value.id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.control_plane.email}"
}

resource "google_kms_crypto_key_iam_member" "cp_signs_audit_heads" {
  for_each      = google_kms_crypto_key.audit_signing
  crypto_key_id = each.value.id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.control_plane.email}"
}

resource "google_kms_crypto_key_iam_member" "cp_envelope" {
  crypto_key_id = google_kms_crypto_key.envelope.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.control_plane.email}"
}
