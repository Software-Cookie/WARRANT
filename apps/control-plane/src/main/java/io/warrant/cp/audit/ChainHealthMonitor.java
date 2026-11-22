package io.warrant.cp.audit;

import io.warrant.cp.tenant.TenantRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Continuously re-verifies every tenant chain end to end, so tampering is detected within one cycle even if nobody
 * asks (Bible §23.2, tampering). A break is logged at ERROR and surfaced on the dashboard.
 */
@Component
public class ChainHealthMonitor {

    private static final Logger LOG = LoggerFactory.getLogger(ChainHealthMonitor.class);

    private final ChainVerificationService verification;
    private final TenantRepository tenants;
    private final Map<String, Health> health = new ConcurrentHashMap<>();

    public ChainHealthMonitor(ChainVerificationService verification, TenantRepository tenants) {
        this.verification = verification;
        this.tenants = tenants;
    }

    public record Health(boolean ok, long verifiedTo, Long brokenAt, String reason, Instant checkedAt) {
    }

    @Scheduled(initialDelay = 5_000, fixedDelay = 30_000)
    public void verifyAll() {
        for (String tenant : tenants.ids()) {
            try {
                ChainVerificationService.Report report = verification.verify(tenant, 1, Long.MAX_VALUE);
                Health result = new Health(report.ok(), report.ok() ? report.to() : report.brokenAt() - 1,
                        report.brokenAt(), report.reason(), Instant.now());
                Health previous = health.put(tenant, result);
                if (!report.ok() && (previous == null || previous.ok())) {
                    LOG.error("AUDIT CHAIN BROKEN tenant={} broken_at={} reason={}", tenant, report.brokenAt(), report.reason());
                }
            } catch (RuntimeException e) {
                LOG.warn("chain verification for {} failed: {}", tenant, e.getClass().getSimpleName());
            }
        }
    }

    public Optional<Health> health(String tenant) {
        return Optional.ofNullable(health.get(tenant));
    }
}
