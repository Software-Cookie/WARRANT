# Runbook: rotate a tenant's signing keys

1. Create a new key version:
   `gcloud kms keys versions create --key <tenant>-warrant --keyring warrant --location <region>`.
2. Update the tenant's `kms_key_uri` to the new version through the admin change-request flow (two security admins).
3. New warrants carry the new `kid`; existing warrants keep verifying until expiry because old public keys stay in
   `key_metadata`. Do not disable the old version before the longest warrant TTL has passed.
4. Rotate audit keys the same way; signed heads record their `kid`, so old heads keep verifying.
