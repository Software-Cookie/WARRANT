package io.warrant.cp.approval;

import io.warrant.cp.identity.AuthFilter;
import io.warrant.cp.identity.Identity;
import io.warrant.cp.identity.Role;
import io.warrant.cp.web.ApiException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/** Approver-facing API behind the console approval view. */
@RestController
@RequestMapping("/v1/escalations")
public class EscalationController {

    public static final String READY_CHANNEL = "warrant:escalations:ready";

    private final EscalationService escalations;
    private final StringRedisTemplate redis;

    public EscalationController(EscalationService escalations, StringRedisTemplate redis) {
        this.escalations = escalations;
        this.redis = redis;
    }

    @GetMapping
    public List<Map<String, Object>> list(@RequestParam(value = "state", defaultValue = "pending") String state,
                                          @RequestParam(value = "limit", defaultValue = "50") int limit,
                                          HttpServletRequest request) {
        Identity identity = AuthFilter.current(request);
        return "pending".equals(state) ? escalations.pending(identity.tenant()) : escalations.recent(identity.tenant(), limit);
    }

    @GetMapping("/{id}")
    public Map<String, Object> detail(@PathVariable("id") String id, HttpServletRequest request) {
        Identity identity = AuthFilter.current(request).requireAny(Role.APPROVER, Role.OWNER, Role.SECURITY_ADMIN);
        return escalations.detail(identity.tenant(), id);
    }

    @PostMapping("/{id}/decision")
    public EscalationModels.Status decide(@PathVariable("id") String id, @RequestBody EscalationModels.DecisionRequest body,
                                          HttpServletRequest request) {
        if (body == null || body.version() == null) {
            throw ApiException.badRequest("action and version are required");
        }
        Identity identity = AuthFilter.current(request);
        EscalationModels.Status status = escalations.decide(identity, id, EscalationService.parseAction(body.action()),
                body.version());
        if (!"denied".equals(status.state())) {
            try {
                redis.convertAndSend(READY_CHANNEL, identity.tenant() + ":" + id);
            } catch (RuntimeException e) {
                // Gateways poll for releasable escalations; the push only shortens the wait.
            }
        }
        return status;
    }
}
