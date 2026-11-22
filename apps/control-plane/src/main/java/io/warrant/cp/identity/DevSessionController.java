package io.warrant.cp.identity;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.warrant.cp.web.ApiException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Development login: issues a session for a seeded console user. Absent outside development environments: the
 * session service bean is never created there and this endpoint answers 404.
 */
@RestController
public class DevSessionController {

    private final ObjectProvider<DevSessionService> sessions;
    private final UserDirectory users;

    public DevSessionController(ObjectProvider<DevSessionService> sessions, UserDirectory users) {
        this.sessions = sessions;
        this.users = users;
    }

    public record SessionRequest(@JsonProperty("email") String email) {
    }

    public record SessionResponse(@JsonProperty("token") String token, @JsonProperty("email") String email,
                                  @JsonProperty("tenants") Map<String, List<String>> tenants,
                                  @JsonProperty("auth_time") Instant authTime) {
    }

    @PostMapping("/v1/dev/session")
    public SessionResponse issue(@RequestBody SessionRequest request) {
        DevSessionService service = sessions.getIfAvailable();
        if (service == null) {
            throw ApiException.notFound("endpoint");
        }
        if (request == null || request.email() == null) {
            throw ApiException.badRequest("email is required");
        }
        Map<String, Set<Role>> membership = users.membership(request.email());
        if (membership.isEmpty()) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "unknown_user", "no console user with that email");
        }
        Map<String, List<String>> tenants = new TreeMap<>();
        membership.forEach((tenant, roles) -> tenants.put(tenant, roles.stream().map(Role::dbName).sorted().toList()));
        return new SessionResponse(service.issue(request.email()), UserDirectory.normalize(request.email()), tenants,
                Instant.now());
    }
}
