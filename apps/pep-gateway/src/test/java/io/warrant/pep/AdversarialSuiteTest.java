package io.warrant.pep;

import com.fasterxml.jackson.databind.JsonNode;
import io.warrant.core.crypto.Base64Url;
import io.warrant.core.ids.Ids;
import io.warrant.core.warrant.Ceiling;
import io.warrant.core.warrant.SignedWarrant;
import io.warrant.core.warrant.Warrant;
import io.warrant.core.warrant.WarrantChain;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Build Specification Milestone 8: each case is an attack that must fail in the specified way. Case 13 (tampered
 * audit row) is exercised against the real chain in the control plane and by chain-verify.
 */
@Tag("adversarial")
class AdversarialSuiteTest extends GatewayTest {

    private static final String READ = "SELECT id FROM vendors WHERE id = 1";

    private String reason(ResponseEntity<JsonNode> response) {
        return response.getBody().path("reason_code").asText();
    }

    @Test
    void case01ForgedSignatureIsInvalidAndNothingIsForwarded() {
        SignedWarrant genuine = defaultWarrant();
        byte[] signature = genuine.signature();
        signature[0] ^= 0x01;
        String forged = "wt1." + Base64Url.encode(genuine.claimsBytes()) + "." + Base64Url.encode(signature);
        int forwarded = WORLD.forwarded.size();
        ResponseEntity<JsonNode> response = send("/v1/proxy/sql.execute", forged, "v1.AAAA", Ids.newId("req"),
                Instant.now(), json(Map.of("arguments", Map.of("q", READ))));
        assertThat(response.getStatusCode().value()).isEqualTo(403);
        assertThat(reason(response)).isEqualTo("INVALID_WARRANT");
        assertThat(WORLD.forwarded).hasSize(forwarded);
    }

    @Test
    void case02ExpiredWarrantAtTtlPlusOneSecondIsExpired() {
        Instant now = Instant.now();
        Warrant base = WORLD.warrants.rootClaims("acme", now.minusSeconds(61), 60, List.of("vendors.read"), 10, 1);
        ResponseEntity<JsonNode> response = proxy(chain(WORLD.warrants.sign(base)), "sql.execute", Map.of("q", READ));
        assertThat(reason(response)).isEqualTo("EXPIRED");
    }

    @Test
    void case03ReplayedWarrantWithMutatedArgumentsFailsTheProof() {
        WarrantChain chain = chain(defaultWarrant());
        String requestId = Ids.newId("req");
        Instant now = Instant.now();
        byte[] input = io.warrant.core.verify.RequestProof.signingInput(chain.leaf().claims().wid(), requestId, now,
                "sql.execute", io.warrant.core.request.ArgumentDigest.of(mapper.valueToTree(Map.of("q", READ))));
        String proof = io.warrant.core.verify.RequestProof.sign(WORLD.warrants.agentKey().getPrivate(), input);
        ResponseEntity<JsonNode> mutated = send("/v1/proxy/sql.execute", chain.encode(), proof, requestId, now,
                json(Map.of("arguments", Map.of("q", "DELETE FROM vendors"))));
        assertThat(reason(mutated)).isEqualTo("INVALID_WARRANT");
        ResponseEntity<JsonNode> exactReplayFirst = proxy(chain, "sql.execute", Map.of("q", READ),
                WORLD.warrants.agentKey(), "req_replayreplay01", now);
        assertThat(exactReplayFirst.getStatusCode().value()).isEqualTo(200);
        ResponseEntity<JsonNode> exactReplay = proxy(chain, "sql.execute", Map.of("q", READ),
                WORLD.warrants.agentKey(), "req_replayreplay01", now);
        assertThat(reason(exactReplay)).isEqualTo("INVALID_WARRANT");
    }

    @Test
    void case04ChildWithWidenedScopeFailsVerification() {
        SignedWarrant parent = root(List.of("vendors.read"), 250, false, 3);
        SignedWarrant widened = WORLD.warrants.sign(WORLD.warrants.childClaims(parent,
                List.of("vendors.read", "vendors.delete"), 100, parent.claims().exp(), 2));
        assertThat(reason(proxy(chain(parent, widened), "sql.execute", Map.of("q", READ)))).isEqualTo("INVALID_WARRANT");
    }

    @Test
    void case05ChildWithExtendedExpiryFailsVerification() {
        SignedWarrant parent = root(List.of("vendors.read"), 250, false, 3);
        SignedWarrant extended = WORLD.warrants.sign(WORLD.warrants.childClaims(parent, List.of("vendors.read"), 100,
                parent.claims().exp() + 3600, 2));
        assertThat(reason(proxy(chain(parent, extended), "sql.execute", Map.of("q", READ)))).isEqualTo("INVALID_WARRANT");
    }

    @Test
    void case06HopDepthFourOnAThreeHopWarrantIsHopLimit() {
        SignedWarrant d0 = root(List.of("vendors.read"), 250, false, 3);
        SignedWarrant d1 = WORLD.warrants.sign(WORLD.warrants.childClaims(d0, List.of("vendors.read"), 250, d0.claims().exp(), 2));
        SignedWarrant d2 = WORLD.warrants.sign(WORLD.warrants.childClaims(d1, List.of("vendors.read"), 250, d0.claims().exp(), 1));
        SignedWarrant d3 = WORLD.warrants.sign(WORLD.warrants.childClaims(d2, List.of("vendors.read"), 250, d0.claims().exp(), 0));
        SignedWarrant d4 = WORLD.warrants.sign(WORLD.warrants.childClaims(d3, List.of("vendors.read"), 250, d0.claims().exp(), 0));
        assertThat(proxy(chain(d0, d1, d2, d3), "sql.execute", Map.of("q", READ)).getStatusCode().value()).isEqualTo(200);
        assertThat(reason(proxy(chain(d0, d1, d2, d3, d4), "sql.execute", Map.of("q", READ)))).isEqualTo("HOP_LIMIT");
    }

    @Test
    void case07InjectionInToolOutputIsDeniedAsIntentDriftAndRecorded() {
        WORLD.classify(40, true, 0.92, 0.9);
        int events = WORLD.appendedEvents.size();
        ResponseEntity<JsonNode> response = proxy(chain(root(List.of("vendors.read", "vendors.archive"), 250, false, 3)),
                "sql.execute", Map.of("q", "DELETE FROM payment_holds WHERE vendor_id = 7"));
        assertThat(reason(response)).isEqualTo("INTENT_DRIFT");
        assertThat(WORLD.appendedEvents).hasSizeGreaterThan(events);
    }

    @Test
    void case08SalamiSlicingIsBlockedAtTheCumulativeCeiling() {
        WarrantChain chain = chain(root(List.of("vendors.archive"), 250, false, 3));
        int allowed = 0;
        String blockedReason = null;
        for (int call = 0; call < 60; call++) {
            int first = call * 5;
            ResponseEntity<JsonNode> response = proxy(chain, "vendors.archive",
                    Map.of("ids", IntStream.range(first, first + 5).boxed().toList()));
            if (response.getStatusCode().value() == 200) {
                allowed++;
            } else {
                blockedReason = reason(response);
                break;
            }
        }
        assertThat(allowed).isEqualTo(50);
        assertThat(blockedReason).isEqualTo("CEILING_EXCEEDED");
    }

    @Test
    void case08bIdenticalCallsServedFromCacheStillCountTowardTheCeiling() {
        WarrantChain chain = chain(root(List.of("vendors.archive"), 25, false, 3));
        Map<String, Object> same = Map.of("ids", List.of(1, 2, 3, 4, 5));
        int allowed = 0;
        for (int call = 0; call < 10; call++) {
            if (proxy(chain, "vendors.archive", same).getStatusCode().value() == 200) {
                allowed++;
            }
        }
        assertThat(allowed).isEqualTo(5);
    }

    @Test
    void case09PermissiveClassifierCannotOverrideAnL1Escalation() {
        WORLD.classify(3, false, 0.0, 1.0);
        ResponseEntity<JsonNode> response = proxy(chain(defaultWarrant()), "sql.execute",
                Map.of("q", "DELETE FROM vendors WHERE id IN (1, 2, 3)"));
        assertThat(response.getStatusCode().value()).isEqualTo(202);
        assertThat(response.getBody().path("decision").asText()).isEqualTo("escalate");
    }

    @Test
    void case10AuditDownPlusIrreversibleWriteIsDeniedAndNotForwarded() throws Exception {
        WORLD.setPolicy("tool \"sql.execute\" { verb \"delete\" { allow } verb \"select\" { allow } }");
        bundles.refresh("acme");
        try {
            WORLD.classify(3, true, 0.05, 0.95);
            WORLD.impact.set(mapper.readTree("{\"available\":true,\"estimated_rows\":3,\"protected\":{}}"));
            WORLD.auditDown.set(true);
            int forwarded = WORLD.forwarded.size();
            SignedWarrant mayDelete = root(List.of("vendors.delete"), 250, true, 3);
            ResponseEntity<JsonNode> response = proxy(chain(mayDelete), "sql.execute",
                    Map.of("q", "DELETE FROM vendors WHERE id IN (1, 2, 3)"));
            assertThat(reason(response)).isEqualTo("AUDIT_UNAVAILABLE");
            assertThat(WORLD.forwarded).hasSize(forwarded);
        } finally {
            WORLD.auditDown.set(false);
            WORLD.setPolicy(io.warrant.policy.PolicyFixturesAccess.repositoryFile("policies/examples/vendors.policy"));
            bundles.refresh("acme");
        }
    }

    @Test
    void case11DirectCallBypassingTheGatewayFailsForLackOfCredential() throws Exception {
        HttpResponse<String> direct = HttpClient.newHttpClient().send(HttpRequest.newBuilder(
                        URI.create(WORLD.targetUrl() + "/tools/vendors.archive"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"ids\":[1]}")).build(), HttpResponse.BodyHandlers.ofString());
        assertThat(direct.statusCode()).isEqualTo(401);
    }

    @Test
    void case12CrossTenantWarrantIsRejectedByKeyMismatch() {
        Warrant globex = WORLD.warrants.rootClaims("globex", Instant.now().minusSeconds(5), 900, List.of("vendors.read"), 10, 1);
        assertThat(reason(proxy(chain(WORLD.warrants.sign(globex)), "sql.execute", Map.of("q", READ))))
                .isEqualTo("INVALID_WARRANT");
        Warrant acmeClaims = WORLD.warrants.rootClaims("acme", Instant.now().minusSeconds(5), 900, List.of("vendors.read"), 10, 1);
        Warrant signedByGlobexKey = new Warrant(acmeClaims.v(), acmeClaims.wid(), "acme", acmeClaims.principal(),
                acmeClaims.agent(), acmeClaims.mandate(), acmeClaims.scope(), new Ceiling(10, false, 0), acmeClaims.iat(),
                acmeClaims.exp(), acmeClaims.hops(), acmeClaims.policyV(), null, acmeClaims.cnf(),
                WORLD.warrants.signerFor("globex").kid());
        SignedWarrant forged = io.warrant.core.warrant.WarrantMinter.mint(signedByGlobexKey, WORLD.warrants.signerFor("globex"));
        assertThat(reason(proxy(chain(forged), "sql.execute", Map.of("q", READ)))).isEqualTo("INVALID_WARRANT");
    }

    @Test
    void case14ClockSkewedTenMinutesForwardIsDenied() {
        Warrant future = WORLD.warrants.rootClaims("acme", Instant.now().plus(Duration.ofMinutes(10)), 900,
                List.of("vendors.read"), 10, 1);
        assertThat(reason(proxy(chain(WORLD.warrants.sign(future)), "sql.execute", Map.of("q", READ))))
                .isEqualTo("INVALID_WARRANT");
        ResponseEntity<JsonNode> skewedRequest = proxy(chain(defaultWarrant()), "sql.execute", Map.of("q", READ),
                WORLD.warrants.agentKey(), Ids.newId("req"), Instant.now().plus(Duration.ofMinutes(10)));
        assertThat(reason(skewedRequest)).isEqualTo("INVALID_WARRANT");
    }

    @Test
    void revokedWarrantIsDeniedOncePropagated() throws Exception {
        SignedWarrant warrant = defaultWarrant();
        WORLD.revoked.add(warrant.claims().wid());
        Thread.sleep(2_500);
        assertThat(reason(proxy(chain(warrant), "sql.execute", Map.of("q", READ)))).isEqualTo("REVOKED");
    }

    @Test
    void stackedSqlStatementsCannotSmuggleAWriteBehindARead() {
        int forwarded = WORLD.forwarded.size();
        ResponseEntity<JsonNode> response = proxy(chain(root(List.of("vendors.read"), 250, false, 3)), "sql.execute",
                Map.of("q", "SELECT 1 FROM vendors; DELETE FROM vendors"));
        assertThat(response.getStatusCode().value()).isIn(202, 403);
        assertThat(WORLD.forwarded).hasSize(forwarded);
    }
}
