# Runbook: classifier unavailable or degraded

Effect: the gateway's circuit opens after repeated failures; L2 decisions fall back to the policy's
`on classifier_unavailable` block (reads allowed, everything else escalates). Nothing becomes more permissive.

1. Check `warrant-classifier` revisions and logs; check the Gemma endpoint (`kubectl -n warrant-models get pods`).
2. If the model is down, set `classifier_backend = "heuristic"` (deterministic, no model) and re-apply.
3. Watch the escalation queue on the dashboard; add approvers if the backlog grows.
