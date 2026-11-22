package io.warrant.cp.approval;

import io.warrant.cp.tenant.TenantRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/** Turns overdue escalations into denials. A timeout never approves. */
@Component
public class EscalationSweeper {

    private static final Logger LOG = LoggerFactory.getLogger(EscalationSweeper.class);

    private final EscalationService escalations;
    private final TenantRepository tenants;

    public EscalationSweeper(EscalationService escalations, TenantRepository tenants) {
        this.escalations = escalations;
        this.tenants = tenants;
    }

    @Scheduled(fixedDelayString = "${warrant.escalation.sweep-interval-ms:1000}")
    public void sweep() {
        for (String tenant : tenants.ids()) {
            try {
                int expired = escalations.expireOverdue(tenant);
                if (expired > 0) {
                    LOG.info("{} escalation(s) for {} timed out and were denied", expired, tenant);
                }
            } catch (RuntimeException e) {
                LOG.warn("escalation sweep for {} failed: {}", tenant, e.getClass().getSimpleName());
            }
        }
    }
}
