package io.warrant.cp.warrant;

import io.warrant.cp.keys.KeyService;
import io.warrant.cp.tenant.Tenant;
import io.warrant.cp.tenant.TenantRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

@Configuration
public class WarrantConfig {

    @Bean
    public WarrantService warrantService(WarrantStore store, AgentDirectory agents, KeyService keys,
                                         TenantRepository tenants, Clock clock) {
        return new WarrantService(store, agents, keys::warrantSigner, tenantId -> {
            Tenant tenant = tenants.find(tenantId).orElseThrow(() -> new IllegalArgumentException("unknown tenant"));
            return new TenantLimits(tenant.maxWarrantTtlSeconds(), tenant.maxCeilingRows(), tenant.maxHops(),
                    tenant.activePolicyVersion());
        }, clock);
    }
}
