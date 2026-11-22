package io.warrant.cp.audit;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.warrant.core.crypto.Base64Url;
import io.warrant.core.crypto.Digests;
import io.warrant.core.crypto.Ed25519;
import io.warrant.core.verify.VerificationKey;
import io.warrant.cp.db.TenantScope;
import io.warrant.cp.keys.KeyService;
import org.springframework.stereotype.Service;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Optional;

/**
 * Recomputes a range of the chain from the stored rows. Reports the first index at which verification breaks:
 * a missing index (deletion), a {@code prev_digest} that does not link, a recomputed digest that differs (an altered
 * field), or a head signature that does not verify.
 */
@Service
public class ChainVerificationService {

    private static final int PAGE = 5_000;

    private final TenantScope scope;
    private final KeyService keys;

    public ChainVerificationService(TenantScope scope, KeyService keys) {
        this.scope = scope;
        this.keys = keys;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Report(
            @JsonProperty("ok") boolean ok,
            @JsonProperty("tenant") String tenant,
            @JsonProperty("from") long from,
            @JsonProperty("to") long to,
            @JsonProperty("checked") long checked,
            @JsonProperty("broken_at") Long brokenAt,
            @JsonProperty("reason") String reason,
            @JsonProperty("signed_heads_verified") long signedHeadsVerified,
            @JsonProperty("last_signed_idx") Long lastSignedIdx,
            @JsonProperty("head_signature") String headSignature,
            @JsonProperty("unsigned_tail") long unsignedTail) {
    }

    public long headIndex(String tenant) {
        return scope.run(tenant, jdbc -> jdbc.query("SELECT last_idx FROM chain_heads WHERE tenant_id = ?",
                (rs, row) -> rs.getLong(1), tenant).stream().findFirst().orElse(0L));
    }

    public Report verify(String tenant, long requestedFrom, long requestedTo) {
        long head = headIndex(tenant);
        long from = Math.max(1, requestedFrom);
        long to = Math.min(requestedTo, head);
        if (head == 0 || from > to) {
            return new Report(true, tenant, from, to, 0, null, head == 0 ? "chain is empty" : "empty range", 0, null, null, 0);
        }
        return scope.run(tenant, jdbc -> {
            State state = new State(from);
            if (from > 1) {
                Optional<String> anchor = jdbc.query("SELECT entry_digest FROM audit_entries WHERE tenant_id = ? AND idx = ?",
                        (rs, row) -> rs.getString(1), tenant, from - 1).stream().findFirst();
                if (anchor.isEmpty()) {
                    return state.broken(tenant, from, to, from - 1, "anchor entry is missing");
                }
                state.running = anchor.get();
            }
            for (long pageStart = from; pageStart <= to && state.brokenAt == null; pageStart += PAGE) {
                long pageEnd = Math.min(to, pageStart + PAGE - 1);
                jdbc.query("SELECT * FROM audit_entries WHERE tenant_id = ? AND idx BETWEEN ? AND ? ORDER BY idx",
                        rs -> {
                            if (state.brokenAt == null) {
                                check(rs, state);
                            }
                        }, tenant, pageStart, pageEnd);
                if (state.brokenAt == null && state.expected <= pageEnd) {
                    state.fail(state.expected, "entry is missing");
                }
            }
            if (state.brokenAt != null) {
                return state.broken(tenant, from, to, state.brokenAt, state.reason);
            }
            long unsigned = state.lastSignedIdx == null ? to - from + 1 : to - state.lastSignedIdx;
            return new Report(true, tenant, from, to, state.checked, null, null, state.signedHeads, state.lastSignedIdx,
                    state.lastSignature, unsigned);
        });
    }

    private void check(ResultSet rs, State state) throws SQLException {
        long idx = rs.getLong("idx");
        if (idx != state.expected) {
            state.fail(state.expected, "entry is missing");
            return;
        }
        ChainRecord record = new ChainRecord(rs.getString("tenant_id"), idx, rs.getString("wid"),
                rs.getString("principal"), rs.getString("agent_id"), rs.getString("tool_id"), rs.getString("verb"),
                rs.getString("target"), rs.getString("arg_digest"), rs.getString("arg_ref"), rs.getString("verdict"),
                rs.getString("reason_code"), rs.getString("policy_v"), rs.getString("model_v"), rs.getString("stage"),
                rs.getString("approver"), rs.getInt("latency_ms"), rs.getTimestamp("decided_at").toInstant());
        String storedPrev = rs.getString("prev_digest");
        String storedDigest = rs.getString("entry_digest");
        if (!Digests.constantTimeEquals(storedPrev, state.running)) {
            state.fail(idx, "prev_digest does not link to entry " + (idx - 1));
            return;
        }
        if (!Digests.constantTimeEquals(record.digest(state.running), storedDigest)) {
            state.fail(idx, "entry contents do not match entry_digest (altered record)");
            return;
        }
        String signature = rs.getString("signature");
        if (signature != null) {
            if (!headSignatureValid(record.tenantId(), idx, storedDigest, signature)) {
                state.fail(idx, "head signature does not verify");
                return;
            }
            state.signedHeads++;
            state.lastSignedIdx = idx;
            state.lastSignature = signature;
        }
        state.running = storedDigest;
        state.expected = idx + 1;
        state.checked++;
    }

    private boolean headSignatureValid(String tenant, long idx, String digest, String signature) {
        int dot = signature.lastIndexOf('.');
        if (dot <= 0) {
            return false;
        }
        Optional<VerificationKey> key = keys.resolve(signature.substring(0, dot));
        if (key.isEmpty() || key.get().purpose() != VerificationKey.KeyPurpose.AUDIT || !key.get().tenant().equals(tenant)) {
            return false;
        }
        try {
            return Ed25519.verify(key.get().key(), ChainRecord.headSigningInput(tenant, idx, digest),
                    Base64Url.decode(signature.substring(dot + 1)));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    public List<VerificationKey> auditKeys(String tenant) {
        return keys.verificationKeys().stream()
                .filter(k -> k.tenant().equals(tenant) && k.purpose() == VerificationKey.KeyPurpose.AUDIT)
                .toList();
    }

    private static final class State {
        long expected;
        String running = ChainRecord.GENESIS;
        long checked;
        long signedHeads;
        Long lastSignedIdx;
        String lastSignature;
        Long brokenAt;
        String reason;

        State(long from) {
            this.expected = from;
        }

        void fail(long idx, String why) {
            brokenAt = idx;
            reason = why;
        }

        Report broken(String tenant, long from, long to, long at, String why) {
            return new Report(false, tenant, from, to, checked, at, why, signedHeads, lastSignedIdx, lastSignature, 0);
        }
    }
}
