package io.warrant.pep.release;

import com.fasterxml.jackson.databind.JsonNode;
import io.warrant.core.registry.ToolDefinition;
import io.warrant.core.warrant.WarrantChain;
import io.warrant.pep.broker.TargetForwarder;
import io.warrant.pep.config.PepProperties;
import io.warrant.pep.cp.ControlPlaneClient;
import io.warrant.pep.pipeline.BundleCache;
import io.warrant.pep.pipeline.TenantBundle;
import io.warrant.pep.pipeline.UsageLedger;
import io.warrant.pep.verify.RevocationCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Releases approved escalations. Parked state lives in the control plane's database, so any gateway instance — not
 * only the one that parked the request, which may have restarted — can claim and forward it. A claim older than a
 * minute can be taken over; the escalation id travels as the idempotency key so a takeover cannot double-execute.
 */
@Component
public class EscalationReleaser {

    private static final Logger LOG = LoggerFactory.getLogger(EscalationReleaser.class);

    private final ControlPlaneClient controlPlane;
    private final BundleCache bundles;
    private final TargetForwarder forwarder;
    private final RevocationCache revocations;
    private final UsageLedger ledger;
    private final PepProperties properties;
    private final String instanceId = "pep-" + UUID.randomUUID();

    public EscalationReleaser(ControlPlaneClient controlPlane, BundleCache bundles, TargetForwarder forwarder,
                              RevocationCache revocations, UsageLedger ledger, PepProperties properties) {
        this.controlPlane = controlPlane;
        this.bundles = bundles;
        this.forwarder = forwarder;
        this.revocations = revocations;
        this.ledger = ledger;
        this.properties = properties;
    }

    @Scheduled(initialDelay = 1_000, fixedDelayString = "${pep.release-poll:PT1S}")
    public void releaseApproved() {
        for (String tenant : properties.tenants()) {
            try {
                controlPlane.getIfOk("/internal/escalations/releasable?tenant=" + ControlPlaneClient.q(tenant),
                        Duration.ofSeconds(2)).ifPresent(ids -> ids.forEach(id -> release(tenant, id.asText())));
            } catch (ControlPlaneClient.ControlPlaneUnavailable e) {
                LOG.debug("release poll for {} failed: {}", tenant, e.getMessage());
            }
        }
    }

    void release(String tenant, String escalationId) {
        ControlPlaneClient.Response claim = controlPlane.post("/internal/escalations/" + ControlPlaneClient.q(escalationId)
                + "/claim?tenant=" + ControlPlaneClient.q(tenant), Map.of("claimant", instanceId), Duration.ofSeconds(3));
        if (claim.status() != 200 || claim.body() == null) {
            return;
        }
        JsonNode ticket = claim.body();
        TargetForwarder.TargetResponse result = forwardTicket(tenant, escalationId, ticket);
        controlPlane.post("/internal/escalations/" + ControlPlaneClient.q(escalationId) + "/result?tenant="
                + ControlPlaneClient.q(tenant), Map.of("status", result.status(), "body", result.body(),
                "claimant", instanceId), Duration.ofSeconds(3));
        LOG.info("released escalation {} ({}) with target status {}", escalationId, ticket.path("state").asText(),
                result.status());
    }

    private TargetForwarder.TargetResponse forwardTicket(String tenant, String escalationId, JsonNode ticket) {
        WarrantChain chain = WarrantChain.parse(ticket.path("warrant_chain").asText());
        for (String wid : chain.wids()) {
            if (revocations.isRevoked(wid)) {
                return new TargetForwarder.TargetResponse(409, com.fasterxml.jackson.databind.node.JsonNodeFactory.instance
                        .objectNode().put("error", "warrant revoked after approval; not forwarded"));
            }
        }
        Optional<TenantBundle> bundle = bundles.forTenant(tenant);
        Optional<ToolDefinition> tool = bundle.flatMap(b -> b.tool(ticket.path("tool_id").asText()));
        if (tool.isEmpty()) {
            return new TargetForwarder.TargetResponse(502, com.fasterxml.jackson.databind.node.JsonNodeFactory.instance
                    .objectNode().put("error", "tool no longer registered"));
        }
        JsonNode arguments = ticket.path("arguments");
        long rows = arguments.path("ids").isArray() ? arguments.path("ids").size() : 0;
        try {
            ledger.chargeApproved(chain, rows);
        } catch (RuntimeException e) {
            LOG.debug("usage ledger unavailable while recording approved rows");
        }
        return forwarder.forward(tool.get(), ticket.path("verb").asText(), arguments,
                ticket.path("request").path("request_id").asText(escalationId), escalationId);
    }
}
