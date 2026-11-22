package io.warrant.cp.audit;

import io.warrant.core.decision.ReasonCode;
import io.warrant.core.decision.Stage;
import io.warrant.core.decision.Verdict;
import io.warrant.core.event.DecisionEvent;
import io.warrant.core.ids.Ids;
import io.warrant.cp.IntegrationTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuditChainTest extends IntegrationTest {

    @Autowired
    AuditChainService chain;

    @Autowired
    ChainVerificationService verification;

    private String tenant;

    @BeforeEach
    void freshTenant() {
        tenant = "t" + Ids.newId("tst").substring(4, 16).toLowerCase(java.util.Locale.ROOT);
        createTenant(tenant);
    }

    static DecisionEvent event(String tenant, int n) {
        boolean deny = n % 7 == 0;
        return new DecisionEvent(tenant, Ids.newId("req"), Ids.newId("wrt"), "r.menon@acme.com",
                "vendor-hygiene@sha256:" + "4f1c".repeat(16), "sql.execute", deny ? "delete" : "select",
                "acme-prod:vendors", "sha256:" + String.format("%064x", n), null,
                deny ? Verdict.DENY : Verdict.ALLOW, deny ? ReasonCode.OUT_OF_SCOPE : null, "2026-11-18.3", null,
                Stage.L1, null, 3, Instant.parse("2026-11-20T09:15:09.284Z").plusMillis(n), null, "test", null);
    }

    private void appendN(int count) {
        List<DecisionEvent> events = new ArrayList<>();
        for (int i = 1; i <= count; i++) {
            events.add(event(tenant, i));
        }
        chain.append(tenant, events);
    }

    @Test
    void validChainOfTenThousandEntriesVerifies() {
        appendN(10_000);
        ChainVerificationService.Report report = verification.verify(tenant, 1, 10_000);
        assertThat(report.ok()).isTrue();
        assertThat(report.checked()).isEqualTo(10_000);
        assertThat(report.signedHeadsVerified()).isGreaterThanOrEqualTo(10);
    }

    @Tag("adversarial")
    @Test
    void alteringOneFieldOfOneEntryBreaksVerificationAtExactlyThatIndex() {
        appendN(200);
        tamper("UPDATE audit_entries SET verdict = 'ALLOW', reason_code = '' WHERE tenant_id = ? AND idx = 77");
        ChainVerificationService.Report report = verification.verify(tenant, 1, 200);
        assertThat(report.ok()).isFalse();
        assertThat(report.brokenAt()).isEqualTo(77);
        assertThat(report.reason()).contains("altered");
    }

    @Tag("adversarial")
    @Test
    void deletingAnEntryBreaksVerificationAtThatIndex() {
        appendN(200);
        tamper("DELETE FROM audit_entries WHERE tenant_id = ? AND idx = 120");
        ChainVerificationService.Report report = verification.verify(tenant, 1, 200);
        assertThat(report.brokenAt()).isEqualTo(120);
        assertThat(report.reason()).contains("missing");
    }

    @Tag("adversarial")
    @Test
    void reorderingTwoEntriesBreaksVerification() {
        appendN(100);
        tamper("UPDATE audit_entries SET idx = -idx WHERE tenant_id = ? AND idx IN (40, 41)");
        tamper("UPDATE audit_entries SET idx = 41 WHERE tenant_id = ? AND idx = -40");
        tamper("UPDATE audit_entries SET idx = 40 WHERE tenant_id = ? AND idx = -41");
        ChainVerificationService.Report report = verification.verify(tenant, 1, 100);
        assertThat(report.ok()).isFalse();
        assertThat(report.brokenAt()).isEqualTo(40);
    }

    @Tag("adversarial")
    @Test
    void recomputingDigestsAfterAnEditIsCaughtByTheSignedHead() {
        appendN(30);
        tamper("UPDATE audit_entries SET signature = 'dev-forged.AAAA' WHERE tenant_id = ? AND signature IS NOT NULL");
        ChainVerificationService.Report report = verification.verify(tenant, 1, 30);
        assertThat(report.ok()).isFalse();
        assertThat(report.reason()).contains("signature");
    }

    @Tag("adversarial")
    @Test
    void applicationRoleCannotUpdateOrDeleteTheChain() {
        appendN(3);
        assertThatThrownBy(() -> scope.run(tenant, jdbc ->
                jdbc.update("UPDATE audit_entries SET verdict = 'ALLOW' WHERE idx = 1")))
                .rootCause().hasMessageContaining("permission denied");
        assertThatThrownBy(() -> scope.run(tenant, jdbc -> jdbc.update("DELETE FROM audit_entries WHERE idx = 1")))
                .rootCause().hasMessageContaining("permission denied");
    }

    @Tag("adversarial")
    @Test
    void ownerCannotRewriteHistoryWithoutDisablingTriggers() {
        appendN(3);
        assertThatThrownBy(() -> asDatabaseOwner().update(
                "UPDATE audit_entries SET verdict = 'ALLOW' WHERE tenant_id = ? AND idx = 1", tenant))
                .rootCause().hasMessageContaining("append-only");
    }

    @Test
    void concurrentAppendsToOneTenantPreserveASingleTotalOrder() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(8);
        List<Future<?>> futures = new ArrayList<>();
        for (int worker = 0; worker < 8; worker++) {
            int offset = worker * 1000;
            futures.add(pool.submit(() -> {
                for (int i = 1; i <= 50; i++) {
                    chain.append(tenant, List.of(event(tenant, offset + i), event(tenant, offset + 500 + i)));
                }
            }));
        }
        for (Future<?> future : futures) {
            future.get(60, TimeUnit.SECONDS);
        }
        pool.shutdown();
        ChainVerificationService.Report report = verification.verify(tenant, 1, Long.MAX_VALUE);
        assertThat(report.ok()).isTrue();
        assertThat(report.checked()).isEqualTo(800);
        Long distinct = scope.run(tenant, jdbc -> jdbc.queryForObject(
                "SELECT count(DISTINCT idx) FROM audit_entries WHERE tenant_id = ?", Long.class, tenant));
        assertThat(distinct).isEqualTo(800);
    }

    @Test
    void appendsToDifferentTenantChainsDoNotContend() throws Exception {
        String other = tenant + "b";
        createTenant(other);
        appendN(1);
        DataSource ds = superuser;
        try (Connection held = ds.getConnection()) {
            held.setAutoCommit(false);
            try (PreparedStatement lock = held.prepareStatement(
                    "SELECT last_idx FROM chain_heads WHERE tenant_id = ? FOR UPDATE")) {
                lock.setString(1, tenant);
                lock.executeQuery();
            }
            CompletableFuture<List<AuditChainService.Appended>> otherTenant = CompletableFuture.supplyAsync(
                    () -> chain.append(other, List.of(event(other, 1))));
            assertThat(otherTenant.get(5, TimeUnit.SECONDS)).hasSize(1);
            CompletableFuture<List<AuditChainService.Appended>> sameTenant = CompletableFuture.supplyAsync(
                    () -> chain.append(tenant, List.of(event(tenant, 2))));
            Thread.sleep(500);
            assertThat(sameTenant).isNotDone();
            held.rollback();
            assertThat(sameTenant.get(10, TimeUnit.SECONDS)).hasSize(1);
        }
    }

    @Test
    void retriedEventsAreAppendedOnce() {
        DecisionEvent once = event(tenant, 1);
        chain.append(tenant, List.of(once));
        List<AuditChainService.Appended> retried = chain.append(tenant, List.of(once));
        assertThat(retried).singleElement().satisfies(a -> assertThat(a.duplicate()).isTrue());
        assertThat(verification.headIndex(tenant)).isEqualTo(1);
    }

    @Tag("adversarial")
    @Test
    void crossTenantQueriesReturnNothingUnderRowLevelSecurity() {
        appendN(5);
        String other = tenant + "x";
        createTenant(other);
        Long visible = scope.run(other, jdbc -> jdbc.queryForObject(
                "SELECT count(*) FROM audit_entries WHERE tenant_id = ?", Long.class, tenant));
        assertThat(visible).isZero();
        Long unscoped = scope.run(other, jdbc -> jdbc.queryForObject("SELECT count(*) FROM audit_entries", Long.class));
        assertThat(unscoped).isZero();
    }

    /** Edits rows the way an attacker with full database access would: triggers disabled for one transaction. */
    private void tamper(String sql) {
        try (Connection connection = superuser.getConnection()) {
            connection.setAutoCommit(false);
            try (var disable = connection.createStatement()) {
                disable.execute("SET LOCAL session_replication_role = replica");
            }
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setString(1, tenant);
                statement.executeUpdate();
            }
            connection.commit();
        } catch (java.sql.SQLException e) {
            throw new IllegalStateException(e);
        }
    }
}
