package io.warrant.cp.policy;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.core.crypto.Digests;
import io.warrant.core.decision.Stage;
import io.warrant.core.decision.Verdict;
import io.warrant.core.event.DecisionEvent;
import io.warrant.core.ids.Ids;
import io.warrant.cp.audit.AuditChainService;
import io.warrant.cp.db.TenantScope;
import io.warrant.cp.tenant.TenantRepository;
import io.warrant.policy.ActionFacts;
import io.warrant.policy.Diagnostic;
import io.warrant.policy.PolicyCompileException;
import io.warrant.policy.PolicyEngine;
import io.warrant.policy.PolicyOutcome;
import io.warrant.policy.PolicyTestRunner;
import io.warrant.policy.compile.PolicyCompiler;
import io.warrant.policy.program.PolicyProgram;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Policy lifecycle: compile with inline diagnostics, run inline tests, replay a candidate against real historical
 * decisions, and publish an immutable version. Publishing requires a clean compile and passing tests, and is
 * itself recorded in the audit chain with the digest of the source.
 */
@Service
public class PolicyService {

    public static final String BUNDLE_CHANNEL = "warrant:bundles";
    private static final Logger LOG = LoggerFactory.getLogger(PolicyService.class);
    private static final Pattern VERSION = Pattern.compile("^\\d{4}-\\d{2}-\\d{2}\\.\\d{1,4}$");

    private final TenantScope scope;
    private final TenantRepository tenants;
    private final AuditChainService chain;
    private final StringRedisTemplate redis;
    private final ObjectMapper mapper;
    private final Clock clock;

    public PolicyService(TenantScope scope, TenantRepository tenants, AuditChainService chain, StringRedisTemplate redis,
                         ObjectMapper mapper, Clock clock) {
        this.scope = scope;
        this.tenants = tenants;
        this.chain = chain;
        this.redis = redis;
        this.mapper = mapper;
        this.clock = clock;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record CompileResult(@JsonProperty("ok") boolean ok,
                                @JsonProperty("diagnostics") List<Diagnostic> diagnostics,
                                @JsonProperty("compiled") JsonNode compiled,
                                @JsonProperty("tests") List<PolicyTestRunner.TestResult> tests) {
    }

    public CompileResult compile(String source) {
        try {
            PolicyCompiler.CompiledPolicy compiled = PolicyCompiler.compile(source);
            return new CompileResult(true, List.of(), compiled.json(), PolicyTestRunner.run(compiled.program()));
        } catch (PolicyCompileException e) {
            return new CompileResult(false, e.diagnostics(), null, null);
        }
    }

    public record ReplayChange(@JsonProperty("request_id") String requestId, @JsonProperty("decided_at") Instant decidedAt,
                               @JsonProperty("tool_id") String toolId, @JsonProperty("verb") String verb,
                               @JsonProperty("target") String target, @JsonProperty("before") String before,
                               @JsonProperty("after") String after, @JsonProperty("reason") String reason) {
    }

    public record ReplayReport(@JsonProperty("evaluated") int evaluated, @JsonProperty("changed") int changed,
                               @JsonProperty("newly_blocked") int newlyBlocked,
                               @JsonProperty("newly_allowed") int newlyAllowed,
                               @JsonProperty("changes") List<ReplayChange> changes) {
    }

    /** Which of the last {@code n} real decisions would change under the candidate policy. */
    public ReplayReport replay(String tenant, String source, int n) {
        PolicyProgram candidate = PolicyCompiler.compile(source).program();
        int limit = Math.min(Math.max(n, 1), 10_000);
        List<Map<String, Object>> rows = scope.run(tenant, jdbc -> jdbc.queryForList("""
                SELECT request_id, decided_at, tool_id, verb, target, verdict, facts::text AS facts
                FROM decision_events WHERE approver IS NULL AND tool_id NOT LIKE 'warrant.%'
                ORDER BY id DESC LIMIT ?
                """, limit));
        List<ReplayChange> changes = new ArrayList<>();
        int newlyBlocked = 0;
        int newlyAllowed = 0;
        int evaluated = 0;
        for (Map<String, Object> row : rows) {
            ActionFacts facts;
            try {
                facts = mapper.readValue((String) row.get("facts"), ActionFacts.class);
            } catch (com.fasterxml.jackson.core.JsonProcessingException | IllegalArgumentException e) {
                continue;
            }
            evaluated++;
            Verdict before = Verdict.valueOf(((String) row.get("verdict")).toUpperCase(Locale.ROOT));
            PolicyOutcome.Decided after = PolicyEngine.decideOffline(candidate, facts);
            if (after.verdict() == before) {
                continue;
            }
            if (after.verdict().stricterThan(before)) {
                newlyBlocked++;
            } else {
                newlyAllowed++;
            }
            changes.add(new ReplayChange((String) row.get("request_id"),
                    ((java.sql.Timestamp) row.get("decided_at")).toInstant(), (String) row.get("tool_id"),
                    (String) row.get("verb"), (String) row.get("target"), before.wireName(), after.verdict().wireName(),
                    after.reason() == null ? null : after.reason().name()));
        }
        return new ReplayReport(evaluated, changes.size(), newlyBlocked, newlyAllowed,
                changes.size() > 200 ? changes.subList(0, 200) : changes);
    }

    public record Published(@JsonProperty("version") String version, @JsonProperty("published_at") Instant publishedAt,
                            @JsonProperty("source_digest") String sourceDigest) {
    }

    public Published publish(String tenant, String source, String requestedVersion, String publishedBy) {
        PolicyCompiler.CompiledPolicy compiled = PolicyCompiler.compile(source);
        List<PolicyTestRunner.TestResult> results = PolicyTestRunner.run(compiled.program());
        if (!PolicyTestRunner.allPassed(results)) {
            throw new IllegalArgumentException("policy tests failed: " + results.stream()
                    .filter(r -> !r.passed()).map(PolicyTestRunner.TestResult::name).toList());
        }
        String version = requestedVersion == null || requestedVersion.isBlank() ? nextVersion(tenant) : requestedVersion;
        if (!VERSION.matcher(version).matches()) {
            throw new IllegalArgumentException("version must look like 2026-11-20.1");
        }
        Instant now = clock.instant();
        String compiledJson;
        try {
            compiledJson = mapper.writeValueAsString(compiled.json());
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("compiled policy not serializable", e);
        }
        scope.runVoid(tenant, jdbc -> {
            int inserted = jdbc.update("""
                    INSERT INTO policies (tenant_id, version, source, compiled, published_at, published_by)
                    VALUES (?, ?, ?, ?::jsonb, ?, ?) ON CONFLICT DO NOTHING
                    """, tenant, version, source, compiledJson, java.sql.Timestamp.from(now), publishedBy);
            if (inserted == 0) {
                throw new IllegalArgumentException("policy version " + version + " already exists; versions are immutable");
            }
            jdbc.update("UPDATE tenants SET active_policy_v = ? WHERE id = ?", version, tenant);
            chain.appendWithin(jdbc, tenant, List.of(adminEvent(tenant, version, compiled.sourceDigest(), publishedBy, now)));
        });
        try {
            redis.convertAndSend(BUNDLE_CHANNEL, tenant);
        } catch (RuntimeException e) {
            LOG.warn("bundle change notification failed; gateways will pick it up on their next poll");
        }
        return new Published(version, now, compiled.sourceDigest());
    }

    private static DecisionEvent adminEvent(String tenant, String version, String sourceDigest, String actor, Instant at) {
        return new DecisionEvent(tenant, Ids.newId("req"), "none", actor, "warrant-console", "warrant.policy", "publish",
                "policy:" + version, sourceDigest, null, Verdict.ALLOW, null, version, null, Stage.L1, actor, 0, at,
                null, "policy " + version + " published", null);
    }

    private String nextVersion(String tenant) {
        String today = LocalDate.ofInstant(clock.instant(), ZoneOffset.UTC).toString();
        Integer count = scope.run(tenant, jdbc -> jdbc.queryForObject(
                "SELECT count(*) FROM policies WHERE tenant_id = ? AND version LIKE ?", Integer.class, tenant, today + ".%"));
        return today + "." + ((count == null ? 0 : count) + 1);
    }

    public record PolicyVersion(@JsonProperty("version") String version, @JsonProperty("source") String source,
                                @JsonProperty("compiled") JsonNode compiled,
                                @JsonProperty("published_at") Instant publishedAt,
                                @JsonProperty("published_by") String publishedBy,
                                @JsonProperty("active") boolean active) {
    }

    public Optional<PolicyVersion> active(String tenant) {
        String version = tenants.find(tenant).map(t -> t.activePolicyVersion()).orElse(null);
        return version == null ? Optional.empty() : get(tenant, version);
    }

    public Optional<PolicyVersion> get(String tenant, String version) {
        String activeVersion = tenants.find(tenant).map(t -> t.activePolicyVersion()).orElse(null);
        return scope.run(tenant, jdbc -> jdbc.query(
                "SELECT version, source, compiled::text AS compiled, published_at, published_by FROM policies WHERE version = ?",
                (rs, row) -> new PolicyVersion(rs.getString("version"), rs.getString("source"),
                        readTree(rs.getString("compiled")), rs.getTimestamp("published_at").toInstant(),
                        rs.getString("published_by"), rs.getString("version").equals(activeVersion)),
                version).stream().findFirst());
    }

    public List<Map<String, Object>> list(String tenant) {
        return scope.run(tenant, jdbc -> jdbc.queryForList(
                "SELECT version, published_at, published_by FROM policies ORDER BY published_at DESC LIMIT 100"));
    }

    private JsonNode readTree(String json) {
        try {
            return mapper.readTree(json);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("stored policy is corrupt");
        }
    }

    public static String digestOf(String source) {
        return Digests.sha256(source);
    }
}
