# Gemma serving on GKE Autopilot (optional L2 model)

The classifier runs on Cloud Run. With `classifier_backend = "gemma"` it calls a self-hosted Gemma 3
instruction-tuned model inside your VPC through an OpenAI-compatible endpoint served by vLLM. Tool-call arguments
therefore never leave your network.

```bash
gcloud container clusters create-auto warrant-models --region asia-south1 \
  --network warrant --subnetwork warrant-run --enable-private-nodes
kubectl apply -f namespace.yaml
# Model weights: accept the Gemma licence on Hugging Face, then store a read token in Secret Manager
#   gcloud secrets create warrant-hf-token --replication-policy=user-managed --locations=asia-south1
#   printf '%s' "$HF_TOKEN" | gcloud secrets versions add warrant-hf-token --data-file=-
# and expose it to the namespace (Secret Manager CSI add-on or External Secrets); the manifest reads secret "hf-token".
kubectl apply -f gemma-vllm.yaml
kubectl -n warrant-models get svc gemma   # internal load balancer IP
terraform apply -var classifier_backend=gemma -var gemma_endpoint=http://<ILB-IP>:8000
```

The service is an internal passthrough load balancer reachable only from the `warrant` VPC, and a NetworkPolicy
admits only VPC traffic on port 8000.
