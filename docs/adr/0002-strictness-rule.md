# ADR 0002: A model verdict can only make a decision stricter

Status: accepted

## Decision
Verdicts are ordered ALLOW < ESCALATE < DENY. The combiner takes the maximum of the L1 floor and the L2 verdict and
never takes L2 alone. Model output is parsed and schema-validated; anything that fails is a failure (low confidence,
which escalates), never an instruction. Arguments reach the model only inside a delimited DATA block whose delimiters
are neutralised.

## Consequences
A degraded or manipulated classifier can cause extra escalations, never an unsafe allow. With the classifier killed
the system keeps working under the policy's `on classifier_unavailable` block. Recall on the dangerous-action corpus
is a CI gate at 100%.
