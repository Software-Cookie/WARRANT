package io.warrant.cp.warrant;

import io.warrant.core.warrant.SignedWarrant;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface WarrantStore {

    void save(SignedWarrant warrant, String encodedChain);

    Optional<StoredWarrant> find(String tenant, String wid);

    /** Revokes the warrant and every warrant derived from it; returns the revoked wids. */
    List<String> revokeWithDescendants(String tenant, String wid, String reason, Instant at);

    boolean isRevoked(String tenant, String wid);

    List<Revocation> revokedSince(String tenant, Instant since);

    List<String> activeForAgent(String tenant, String agentName, Instant now);

    List<StoredWarrant> recent(String tenant, int limit);

    record StoredWarrant(String wid, String tenant, String principal, String agentId, String mandate,
                         List<String> scope, String parentWid, int hopsLeft, String policyV, Instant issuedAt,
                         Instant expiresAt, Instant revokedAt, String chain) {
    }

    record Revocation(String wid, Instant revokedAt) {
    }
}
