package io.warrant.cp.policy;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.warrant.cp.identity.AuthFilter;
import io.warrant.cp.identity.Identity;
import io.warrant.cp.identity.Role;
import io.warrant.cp.web.ApiException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/v1/policies")
public class PolicyController {

    private static final Role[] AUTHORS = {Role.DEVELOPER, Role.SECURITY_ADMIN, Role.OWNER};
    private static final int MAX_SOURCE = 512 * 1024;

    private final PolicyService policies;

    public PolicyController(PolicyService policies) {
        this.policies = policies;
    }

    public record SourceBody(@JsonProperty("source") String source, @JsonProperty("version") String version,
                             @JsonProperty("n") Integer n) {
        String requireSource() {
            if (source == null || source.isBlank()) {
                throw ApiException.badRequest("source is required");
            }
            if (source.length() > MAX_SOURCE) {
                throw ApiException.badRequest("policy source too large");
            }
            return source;
        }
    }

    @PostMapping("/compile")
    public PolicyService.CompileResult compile(@RequestBody SourceBody body, HttpServletRequest request) {
        AuthFilter.current(request).requireAny(AUTHORS);
        return policies.compile(body.requireSource());
    }

    @PostMapping("/test")
    public PolicyService.CompileResult test(@RequestBody SourceBody body, HttpServletRequest request) {
        AuthFilter.current(request).requireAny(AUTHORS);
        return policies.compile(body.requireSource());
    }

    @PostMapping("/replay")
    public PolicyService.ReplayReport replay(@RequestBody SourceBody body, HttpServletRequest request) {
        Identity identity = AuthFilter.current(request).requireAny(AUTHORS);
        return policies.replay(identity.tenant(), body.requireSource(), body.n() == null ? 1000 : body.n());
    }

    /** Publishing is reserved to security administrators: the author of a policy change is not its approver. */
    @PostMapping("/publish")
    public ResponseEntity<PolicyService.Published> publish(@RequestBody SourceBody body, HttpServletRequest request) {
        Identity identity = AuthFilter.current(request).requireAny(Role.SECURITY_ADMIN, Role.OWNER);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(policies.publish(identity.tenant(), body.requireSource(), body.version(), identity.email()));
    }

    @GetMapping
    public List<Map<String, Object>> list(HttpServletRequest request) {
        return policies.list(AuthFilter.current(request).tenant());
    }

    @GetMapping("/active")
    public PolicyService.PolicyVersion active(HttpServletRequest request) {
        return policies.active(AuthFilter.current(request).tenant()).orElseThrow(() -> ApiException.notFound("active policy"));
    }

    @GetMapping("/{version}")
    public PolicyService.PolicyVersion get(@PathVariable("version") String version, HttpServletRequest request) {
        return policies.get(AuthFilter.current(request).tenant(), version).orElseThrow(() -> ApiException.notFound("policy"));
    }
}
