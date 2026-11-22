package io.warrant.cp.approval;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.core.decision.ReasonCode;
import io.warrant.core.decision.Stage;
import io.warrant.core.decision.Verdict;
import io.warrant.core.event.DecisionEvent;
import io.warrant.core.ids.Ids;
import io.warrant.core.warrant.Ceiling;
import io.warrant.cp.Fixtures;
import io.warrant.cp.IntegrationTest;
import io.warrant.cp.identity.Identity;
import io.warrant.cp.identity.Role;
import io.warrant.cp.identity.UserDirectory;
import io.warrant.cp.policy.PolicyService;
import io.warrant.cp.warrant.AgentDirectory;
import io.warrant.cp.warrant.IssueCommand;
import io.warrant.cp.warrant.WarrantService;
import io.warrant.cp.web.ApiException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Instant;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EscalationLifecycleTest extends IntegrationTest {

    @Autowired
    EscalationService escalations;
    @Autowired
    WarrantService warrants;
    @Autowired
    UserDirectory users;
    @Autowired
    AgentDirectory agents;
    @Autowired
    PolicyService policies;
    @Autowired
    ObjectMapper mapper;

    private String tenant;
    private String chain;

    @BeforeEach
    void seed() {
        tenant = "esc" + Ids.newId("tst").substring(18).toLowerCase(java.util.Locale.ROOT);
        Fixtures.seedTenant(this, tenant, users, agents, policies);
        chain = warrants.issue(new IssueCommand(tenant, "r.menon@acme.com", "vendor-hygiene", Fixtures.BUILD,
                "clean up stale vendor records", List.of("vendors.read", "vendors.archive"), new Ceiling(250, false, 0),
                900, 3, Fixtures.cnf(Fixtures.agentKey()))).chain().encode();
    }

    private EscalationModels.ParkRequest park(String coalesceKey, boolean withAlternative) {
        String requestId = Ids.newId("req");
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("request_id", requestId);
        request.put("tool_id", "sql.execute");
        request.put("verb", "delete");
        request.put("target", "acme-prod:vendors");
        request.put("arg_digest", "sha256:" + "a".repeat(64));
        request.put("permissions", List.of("vendors.delete"));
        request.put("principal", "r.menon@acme.com");
        request.put("agent", "vendor-hygiene@" + Fixtures.BUILD);
        Map<String, Object> card = Map.of("headline", "Agent wants to permanently delete 1,284 vendors",
                "risk", "212 have open invoices and 7 are under active audit.",
                "facts", Map.of("rows", 1284, "reversible", false));
        EscalationModels.Alternative alternative = withAlternative
                ? new EscalationModels.Alternative("vendors.archive", "archive", "vendors.archive",
                mapper.valueToTree(Map.of("ids", List.of(1, 2, 3))), 1072, "Archive 1,072 safe")
                : null;
        DecisionEvent audit = new DecisionEvent(tenant, requestId, io.warrant.core.warrant.WarrantChain.parse(chain).leaf()
                .claims().wid(), "r.menon@acme.com", "vendor-hygiene@" + Fixtures.BUILD, "sql.execute", "delete",
                "acme-prod:vendors", "sha256:" + "a".repeat(64), null, Verdict.ESCALATE, ReasonCode.PROTECTED_RECORDS,
                "2026-11-18.3", "heuristic-v1", Stage.L2, null, 210, Instant.now(), null, "held", null);
        return new EscalationModels.ParkRequest(tenant, request,
                mapper.valueToTree(Map.of("q", "DELETE FROM vendors WHERE last_activity < now() - interval '18 months'")),
                chain, card, alternative, coalesceKey, "high", audit);
    }

    private Identity approver(Instant authTime) {
        return new Identity(tenant, "r.menon@acme.com", EnumSet.of(Role.APPROVER), authTime);
    }

    @Test
    void escalateThenApproveReleasesTheOriginalCallOnce() {
        EscalationModels.Parked parked = escalations.park(park(Ids.newId("key"), false));
        assertThat(escalations.pending(tenant)).extracting(m -> m.get("id")).contains(parked.escalationId());
        EscalationModels.Status decided = escalations.decide(approver(Instant.now()), parked.escalationId(),
                EscalationModels.Action.APPROVE, 0);
        assertThat(decided.state()).isEqualTo("approved");
        assertThat(escalations.releasable(tenant, 10)).contains(parked.escalationId());
        EscalationModels.ReleaseTicket ticket = escalations.claim(tenant, parked.escalationId(), "pep-1").orElseThrow();
        assertThat(ticket.toolId()).isEqualTo("sql.execute");
        assertThat(ticket.arguments().path("q").asText()).startsWith("DELETE FROM vendors");
        assertThat(escalations.claim(tenant, parked.escalationId(), "pep-2")).isEmpty();
        escalations.recordResult(tenant, parked.escalationId(),
                new EscalationModels.ReleaseResult(200, mapper.valueToTree(Map.of("deleted", 1284)), "pep-1"));
        EscalationModels.Status status = escalations.statusForAgent(tenant, parked.escalationId(),
                io.warrant.core.warrant.WarrantChain.parse(chain).wids()).orElseThrow();
        assertThat(status.releaseState()).isEqualTo("released");
        assertThat(status.result().path("deleted").asInt()).isEqualTo(1284);
    }

    @Tag("adversarial")
    @Test
    void timeoutMeansDeniedAndNothingIsReleased() throws Exception {
        scope.runVoid(tenant, jdbc -> jdbc.update("UPDATE tenants SET escalation_ttl_seconds = 30 WHERE id = ?", tenant));
        EscalationModels.Parked parked = escalations.park(park(Ids.newId("key"), false));
        scope.runVoid(tenant, jdbc -> jdbc.update("UPDATE escalations SET expires_at = now() - interval '1 second' WHERE id = ?",
                parked.escalationId()));
        assertThat(escalations.expireOverdue(tenant)).isEqualTo(1);
        EscalationModels.Status status = escalations.statusForAgent(tenant, parked.escalationId(),
                io.warrant.core.warrant.WarrantChain.parse(chain).wids()).orElseThrow();
        assertThat(status.state()).isEqualTo("timeout");
        assertThat(escalations.releasable(tenant, 10)).doesNotContain(parked.escalationId());
        assertThatThrownBy(() -> escalations.decide(approver(Instant.now()), parked.escalationId(),
                EscalationModels.Action.APPROVE, 1)).isInstanceOf(ApiException.class);
        String reason = scope.run(tenant, jdbc -> jdbc.queryForObject(
                "SELECT reason_code FROM audit_entries WHERE tenant_id = ? ORDER BY idx DESC LIMIT 1", String.class, tenant));
        assertThat(reason).isEqualTo("APPROVAL_TIMEOUT");
    }

    @Test
    void partialApprovalReleasesOnlyTheApprovedSubset() {
        EscalationModels.Parked parked = escalations.park(park(Ids.newId("key"), true));
        EscalationModels.Status decided = escalations.decide(approver(Instant.now()), parked.escalationId(),
                EscalationModels.Action.APPROVE_PARTIAL, 0);
        assertThat(decided.state()).isEqualTo("partial");
        assertThat(decided.appliedScope()).containsExactly("vendors.archive");
        EscalationModels.ReleaseTicket ticket = escalations.claim(tenant, parked.escalationId(), "pep-1").orElseThrow();
        assertThat(ticket.toolId()).isEqualTo("vendors.archive");
        assertThat(ticket.arguments().path("ids")).hasSize(3);
    }

    @Tag("adversarial")
    @Test
    void doubleApprovalIsRejectedByTheOptimisticLock() {
        EscalationModels.Parked parked = escalations.park(park(Ids.newId("key"), false));
        escalations.decide(approver(Instant.now()), parked.escalationId(), EscalationModels.Action.APPROVE, 0);
        assertThatThrownBy(() -> escalations.decide(approver(Instant.now()), parked.escalationId(),
                EscalationModels.Action.APPROVE, 0))
                .isInstanceOf(ApiException.class).hasMessageContaining("already approved");
    }

    @Tag("adversarial")
    @Test
    void highSeverityApprovalRequiresAFreshIdentityAssertion() {
        EscalationModels.Parked parked = escalations.park(park(Ids.newId("key"), false));
        assertThatThrownBy(() -> escalations.decide(approver(Instant.now().minusSeconds(3600)), parked.escalationId(),
                EscalationModels.Action.APPROVE, 0))
                .isInstanceOf(ApiException.class).hasMessageContaining("fresh sign-in");
    }

    @Tag("adversarial")
    @Test
    void developersCannotApprove() {
        EscalationModels.Parked parked = escalations.park(park(Ids.newId("key"), false));
        Identity developer = new Identity(tenant, "meera@acme.com", EnumSet.of(Role.DEVELOPER), Instant.now());
        assertThatThrownBy(() -> escalations.decide(developer, parked.escalationId(), EscalationModels.Action.APPROVE, 0))
                .isInstanceOf(ApiException.class);
    }

    @Test
    void similarCallsFromOneRunAreCoalescedIntoOneCard() {
        String key = Ids.newId("key");
        EscalationModels.Parked first = escalations.park(park(key, false));
        EscalationModels.Parked second = escalations.park(park(key, false));
        assertThat(second.coalescedInto()).isEqualTo(first.escalationId());
        assertThat(escalations.pending(tenant)).hasSize(1);
        escalations.decide(approver(Instant.now()), first.escalationId(), EscalationModels.Action.DENY, 0);
        EscalationModels.Status member = escalations.statusForAgent(tenant, second.escalationId(),
                io.warrant.core.warrant.WarrantChain.parse(chain).wids()).orElseThrow();
        assertThat(member.state()).isEqualTo("denied");
    }

    @Tag("adversarial")
    @Test
    void withEveryChannelDownTheEscalationStaysPendingAndIsNeverAutoApproved() throws Exception {
        EscalationModels.Parked parked = escalations.park(park(Ids.newId("key"), false));
        Thread.sleep(500);
        String state = scope.run(tenant, jdbc -> jdbc.queryForObject("SELECT state FROM escalations WHERE id = ?",
                String.class, parked.escalationId()));
        assertThat(state).isEqualTo("pending");
        assertThat(escalations.releasable(tenant, 10)).doesNotContain(parked.escalationId());
    }

    @Tag("adversarial")
    @Test
    void parkedArgumentsAreEncryptedAtRest() {
        EscalationModels.Parked parked = escalations.park(park(Ids.newId("key"), false));
        byte[] stored = asDatabaseOwner().queryForObject("SELECT arguments_enc FROM escalations WHERE id = ?",
                byte[].class, parked.escalationId());
        assertThat(new String(stored, java.nio.charset.StandardCharsets.ISO_8859_1)).doesNotContain("DELETE FROM vendors");
    }
}
