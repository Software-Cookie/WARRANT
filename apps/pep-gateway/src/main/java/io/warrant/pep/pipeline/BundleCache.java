package io.warrant.pep.pipeline;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.core.registry.ToolDefinition;
import io.warrant.pep.config.PepProperties;
import io.warrant.pep.cp.ControlPlaneClient;
import io.warrant.policy.program.PolicyProgram;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Last-known-good policy bundle per tenant. Polled from the control plane; if the control plane is unreachable the
 * gateway keeps deciding on the version it has and reports staleness, alerting once it exceeds the configured bound.
 */
@Component
public class BundleCache {

    private static final Logger LOG = LoggerFactory.getLogger(BundleCache.class);

    private final ControlPlaneClient controlPlane;
    private final PepProperties properties;
    private final ObjectMapper mapper;
    private final Clock clock;
    private final Map<String, TenantBundle> bundles = new ConcurrentHashMap<>();
    private final Map<String, Instant> lastSuccess = new ConcurrentHashMap<>();

    public BundleCache(ControlPlaneClient controlPlane, PepProperties properties, ObjectMapper mapper, Clock clock) {
        this.controlPlane = controlPlane;
        this.properties = properties;
        this.mapper = mapper;
        this.clock = clock;
    }

    public Optional<TenantBundle> forTenant(String tenant) {
        TenantBundle bundle = bundles.get(tenant);
        if (bundle == null && properties.serves(tenant)) {
            refresh(tenant);
            bundle = bundles.get(tenant);
        }
        return Optional.ofNullable(bundle);
    }

    public Duration staleness(String tenant) {
        Instant last = lastSuccess.get(tenant);
        return last == null ? Duration.ofDays(365) : Duration.between(last, clock.instant());
    }

    @Scheduled(initialDelay = 0, fixedDelayString = "${pep.bundle-poll:PT5S}")
    public void refreshAll() {
        for (String tenant : properties.tenants()) {
            refresh(tenant);
            Duration stale = staleness(tenant);
            if (bundles.containsKey(tenant) && stale.compareTo(properties.policyStalenessAlert()) > 0) {
                LOG.warn("POLICY STALE tenant={} serving {} for {}s without reaching the control plane", tenant,
                        bundles.get(tenant).bundleVersion(), stale.toSeconds());
            }
        }
    }

    public void refresh(String tenant) {
        TenantBundle current = bundles.get(tenant);
        String have = current == null ? "" : "&have=" + ControlPlaneClient.q(current.bundleVersion());
        try {
            ControlPlaneClient.Response response = controlPlane.get("/internal/bundle?tenant="
                    + ControlPlaneClient.q(tenant) + have, Duration.ofSeconds(3));
            if (response.status() == 304) {
                lastSuccess.put(tenant, clock.instant());
                return;
            }
            if (!response.ok() || response.body() == null) {
                LOG.warn("bundle for {} unavailable (HTTP {})", tenant, response.status());
                return;
            }
            bundles.put(tenant, parse(tenant, response.body()));
            lastSuccess.put(tenant, clock.instant());
            LOG.info("loaded policy bundle {} for {}", bundles.get(tenant).bundleVersion(), tenant);
        } catch (ControlPlaneClient.ControlPlaneUnavailable e) {
            LOG.debug("bundle poll for {} failed: {}", tenant, e.getMessage());
        } catch (RuntimeException e) {
            LOG.error("rejected malformed bundle for {}: {}", tenant, e.getClass().getSimpleName());
        }
    }

    TenantBundle parse(String tenant, JsonNode body) {
        PolicyProgram program = PolicyProgram.load(body.path("compiled"));
        Map<String, ToolDefinition> tools = new LinkedHashMap<>();
        List<ToolDefinition> definitions = mapper.convertValue(body.path("tools"), new TypeReference<>() { });
        definitions.forEach(t -> tools.put(t.id(), t));
        JsonNode tenantSettings = body.path("tenant_settings");
        Map<String, Object> settings = mapper.convertValue(tenantSettings.path("settings"), new TypeReference<>() { });
        return new TenantBundle(tenant, body.path("bundle_version").asText(), body.path("policy_version").asText(),
                program, Map.copyOf(tools), settings == null ? Map.of() : settings,
                tenantSettings.path("fail_mode").asText("closed"), tenantSettings.path("escalation_ttl_seconds").asInt(900),
                clock.instant());
    }

    public void install(TenantBundle bundle) {
        bundles.put(bundle.tenant(), bundle);
        lastSuccess.put(bundle.tenant(), clock.instant());
    }
}
