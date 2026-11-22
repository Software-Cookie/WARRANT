# ADR 0001: The gateway is the enforcement point; agents never hold target credentials

Status: accepted

## Context
An agent that holds a credential can use all of its authority. Advisory checks inside the agent fail exactly when
the agent is manipulated (prompt injection through tool output).

## Decision
All tool calls go through `pep-gateway`. Target credentials live in Secret Manager and are fetched by reference per
request, held in memory for that request only, injected into the forwarded call and never logged or returned.
Agents present a warrant chain plus an Ed25519 proof of possession over the request.

## Consequences
* A compromised agent can at most request; it cannot act.
* The gateway is on the hot path: it is stateless, horizontally scaled, with minimum instances kept warm.
* A direct call to a target without the gateway fails (tested in `DecisionPipelineTest`).
