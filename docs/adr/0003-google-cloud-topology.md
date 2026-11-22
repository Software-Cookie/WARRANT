# ADR 0003: Google Cloud topology

Status: accepted

## Decision
* Cloud Run for gateway, control plane, classifier and console; Direct VPC egress to private Cloud SQL and
  Memorystore; Cloud NAT for outbound internet with a stable address.
* External HTTPS load balancer with Cloud Armor (OWASP CRS, rate limiting, `/internal` blocked) in front of console,
  API and gateway; their Cloud Run ingress admits only the load balancer and the VPC.
* Classifier ingress is internal-only and requires the gateway's Google ID token (Cloud Run IAM).
* Optional self-hosted Gemma on GKE Autopilot with L4 GPUs behind an internal load balancer, so tool-call arguments
  never leave the VPC. Gemini on Vertex AI words approval cards from metadata and counts only.
* Cloud KMS (HSM) for warrant and audit signing per tenant and for the envelope key.

## Consequences
No service is directly internet-reachable except through the load balancer; no data store has a public address.
