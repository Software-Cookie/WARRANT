# Runbook: audit chain reported broken

Signal: dashboard shows "Audit chain: Broken", an alert from `ChainHealthMonitor`, or `warrant audit verify` exits 1.

1. Do not repair anything in place. The break index and reason are the evidence.
2. Export an evidence pack around the break:
   `warrant audit export --format evidence-pack --from <n-100> --to <n+100> --out break.zip`.
3. Verify independently with `packages/chain-verify` on a clean machine (it depends on nothing else).
4. Check Cloud SQL and Cloud Audit Logs for `ALTER TABLE ... DISABLE TRIGGER` or direct writes, and who made them.
5. Treat it as a security incident: review database IAM bindings and KMS key access, notify the tenant's security
   contact. Signed heads after the break still prove what the chain contained when they were signed.
