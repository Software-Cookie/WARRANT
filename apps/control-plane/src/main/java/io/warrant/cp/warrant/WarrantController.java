package io.warrant.cp.warrant;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import io.warrant.core.warrant.Ceiling;
import io.warrant.core.warrant.Warrant;
import io.warrant.cp.identity.AuthFilter;
import io.warrant.cp.identity.Identity;
import io.warrant.cp.identity.Role;
import io.warrant.cp.web.ApiException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/v1/warrants")
public class WarrantController {

    public static final String DERIVE_OPERATION = "warrant.derive";

    private final WarrantService warrants;
    private final WarrantStore store;
    private final AgentRequestAuthenticator agentAuth;
    private final RevocationPublisher revocations;

    public WarrantController(WarrantService warrants, WarrantStore store, AgentRequestAuthenticator agentAuth,
                             RevocationPublisher revocations) {
        this.warrants = warrants;
        this.store = store;
        this.agentAuth = agentAuth;
        this.revocations = revocations;
    }

    public record CeilingBody(@JsonProperty("rows") long rows, @JsonProperty("irreversible") boolean irreversible,
                              @JsonProperty("spend") long spend) {
        Ceiling toCeiling() {
            return new Ceiling(rows, irreversible, spend);
        }
    }

    public record IssueBody(@JsonProperty("agent") String agent, @JsonProperty("build_hash") String buildHash,
                            @JsonProperty("mandate") String mandate, @JsonProperty("scope") List<String> scope,
                            @JsonProperty("ceiling") CeilingBody ceiling, @JsonProperty("ttl_seconds") long ttlSeconds,
                            @JsonProperty("hops") int hops, @JsonProperty("cnf") String cnf) {
    }

    public record WarrantResponse(@JsonProperty("wid") String wid, @JsonProperty("warrant") Warrant warrant,
                                  @JsonProperty("token") String token, @JsonProperty("expires_at") Instant expiresAt) {
        static WarrantResponse of(WarrantService.Issued issued) {
            Warrant claims = issued.warrant().claims();
            return new WarrantResponse(claims.wid(), claims, issued.chain().encode(), claims.expiresAt());
        }
    }

    @PostMapping
    public ResponseEntity<WarrantResponse> issue(@RequestBody IssueBody body, HttpServletRequest request) {
        Identity identity = AuthFilter.current(request)
                .requireAny(Role.OWNER, Role.SECURITY_ADMIN, Role.APPROVER, Role.DEVELOPER);
        if (body == null || body.ceiling() == null || body.scope() == null) {
            throw ApiException.badRequest("agent, build_hash, mandate, scope, ceiling, ttl_seconds, hops and cnf are required");
        }
        WarrantService.Issued issued = warrants.issue(new IssueCommand(identity.tenant(), identity.email(),
                body.agent(), body.buildHash(), body.mandate(), body.scope(), body.ceiling().toCeiling(),
                body.ttlSeconds(), body.hops(), body.cnf()));
        return ResponseEntity.status(HttpStatus.CREATED).body(WarrantResponse.of(issued));
    }

    /** Called by an agent holding the parent warrant. Authenticated by the chain and a proof over this body. */
    @PostMapping("/{wid}/derive")
    public ResponseEntity<WarrantResponse> derive(@PathVariable("wid") String wid, @RequestBody byte[] body,
                                                  HttpServletRequest request) {
        AgentRequestAuthenticator.Authenticated caller = agentAuth.authenticate(request, body, DERIVE_OPERATION);
        if (!caller.chain().leaf().claims().wid().equals(wid)) {
            throw ApiException.badRequest("the presented warrant is not " + wid);
        }
        JsonNode narrowing = caller.body();
        DeriveCommand command = new DeriveCommand(
                strings(narrowing.path("scope")),
                new Ceiling(narrowing.path("ceiling").path("rows").asLong(-1),
                        narrowing.path("ceiling").path("irreversible").asBoolean(false),
                        narrowing.path("ceiling").path("spend").asLong(0)),
                narrowing.path("ttl_seconds").asLong(0),
                narrowing.path("cnf").asText(null),
                narrowing.hasNonNull("agent") ? narrowing.path("agent").asText() : null,
                narrowing.hasNonNull("build_hash") ? narrowing.path("build_hash").asText() : null);
        return ResponseEntity.status(HttpStatus.CREATED).body(WarrantResponse.of(warrants.derive(caller.chain(), command)));
    }

    @DeleteMapping("/{wid}")
    public ResponseEntity<Map<String, Object>> revoke(@PathVariable("wid") String wid,
                                                      @RequestParam(value = "reason", required = false) String reason,
                                                      HttpServletRequest request) {
        Identity identity = AuthFilter.current(request);
        WarrantStore.StoredWarrant stored = store.find(identity.tenant(), wid)
                .orElseThrow(() -> ApiException.notFound("warrant"));
        boolean isPrincipal = stored.principal().equals(identity.email());
        if (!isPrincipal && !identity.has(Role.SECURITY_ADMIN) && !identity.has(Role.OWNER)) {
            throw ApiException.forbidden("only the principal or a security administrator can revoke a warrant");
        }
        List<String> revoked = warrants.revoke(identity.tenant(), wid,
                reason == null ? "revoked by " + identity.email() : reason);
        revocations.publish(identity.tenant(), revoked);
        return ResponseEntity.ok(Map.of("revoked", revoked));
    }

    @GetMapping("/{wid}")
    public WarrantStore.StoredWarrant get(@PathVariable("wid") String wid, HttpServletRequest request) {
        Identity identity = AuthFilter.current(request);
        return store.find(identity.tenant(), wid).orElseThrow(() -> ApiException.notFound("warrant"));
    }

    @GetMapping
    public List<WarrantStore.StoredWarrant> recent(@RequestParam(value = "limit", defaultValue = "50") int limit,
                                                   HttpServletRequest request) {
        return store.recent(AuthFilter.current(request).tenant(), limit);
    }

    private static List<String> strings(JsonNode array) {
        if (!array.isArray()) {
            throw ApiException.badRequest("scope must be an array of permissions");
        }
        List<String> out = new ArrayList<>();
        array.forEach(node -> out.add(node.asText()));
        return out;
    }
}
