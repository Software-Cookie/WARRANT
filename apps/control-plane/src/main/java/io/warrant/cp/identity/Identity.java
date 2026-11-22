package io.warrant.cp.identity;

import io.warrant.cp.web.ApiException;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Set;

/** An authenticated console user acting within one tenant. */
public record Identity(String tenant, String email, Set<Role> roles, Instant authTime) {

    public Identity {
        roles = Set.copyOf(roles);
    }

    public boolean has(Role role) {
        return roles.contains(role);
    }

    public Identity requireAny(Role... allowed) {
        if (Arrays.stream(allowed).noneMatch(roles::contains)) {
            throw ApiException.forbidden("requires one of the roles " + Arrays.toString(allowed));
        }
        return this;
    }

    public boolean authenticatedWithin(Duration window, Instant now) {
        return authTime != null && !authTime.isBefore(now.minus(window));
    }
}
