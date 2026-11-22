package io.warrant.core.warrant;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.warrant.core.crypto.Base64Url;
import io.warrant.core.crypto.Ed25519;
import io.warrant.core.ids.Ids;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * The signed claims of a warrant (Build Specification §1). Every field is covered by the signature.
 *
 * <p>{@code cnf} binds the warrant to the agent run's Ed25519 key: every request must carry a proof signed by
 * that key over the request's argument digest, so a stolen warrant cannot be replayed with other arguments.
 */
public record Warrant(
        @JsonProperty("v") int v,
        @JsonProperty("wid") String wid,
        @JsonProperty("tenant") String tenant,
        @JsonProperty("principal") String principal,
        @JsonProperty("agent") String agent,
        @JsonProperty("mandate") String mandate,
        @JsonProperty("scope") List<String> scope,
        @JsonProperty("ceiling") Ceiling ceiling,
        @JsonProperty("iat") long iat,
        @JsonProperty("exp") long exp,
        @JsonProperty("hops") int hops,
        @JsonProperty("policy_v") String policyV,
        @JsonProperty("parent") ParentRef parent,
        @JsonProperty("cnf") String cnf,
        @JsonProperty("kid") String kid) {

    public static final int FORMAT_VERSION = 1;
    public static final int MAX_HOPS = 16;
    public static final Duration MAX_LIFETIME = Duration.ofDays(7);
    public static final int MAX_MANDATE_LENGTH = 2000;

    private static final Pattern TENANT = Pattern.compile("^[a-z0-9][a-z0-9-]{1,62}$");
    private static final Pattern AGENT = Pattern.compile("^[a-z0-9][a-z0-9._-]{0,63}@sha256:[0-9a-f]{64}$");
    private static final Pattern POLICY_VERSION = Pattern.compile("^[A-Za-z0-9._:+-]{1,128}$");
    private static final Pattern KID = Pattern.compile("^[A-Za-z0-9._:-]{1,128}$");

    public Warrant {
        if (v != FORMAT_VERSION) {
            throw new IllegalArgumentException("unsupported warrant format version " + v);
        }
        if (!Ids.isWellFormed(wid, "wrt")) {
            throw new IllegalArgumentException("wid malformed");
        }
        requireMatch(TENANT, tenant, "tenant");
        principal = requirePrintable(principal, "principal", 320, false);
        requireMatch(AGENT, agent, "agent");
        mandate = requirePrintable(mandate, "mandate", MAX_MANDATE_LENGTH, true);
        scope = normalizeScope(scope);
        Objects.requireNonNull(ceiling, "ceiling");
        if (iat < 0 || exp <= iat) {
            throw new IllegalArgumentException("exp must be after iat");
        }
        if (exp - iat > MAX_LIFETIME.toSeconds()) {
            throw new IllegalArgumentException("warrant lifetime exceeds " + MAX_LIFETIME);
        }
        if (hops < 0 || hops > MAX_HOPS) {
            throw new IllegalArgumentException("hops out of range: " + hops);
        }
        requireMatch(POLICY_VERSION, policyV, "policy_v");
        if (cnf == null || Base64Url.decode(cnf).length != Ed25519.RAW_PUBLIC_KEY_LENGTH) {
            throw new IllegalArgumentException("cnf must be a base64url Ed25519 public key");
        }
        requireMatch(KID, kid, "kid");
    }

    private static void requireMatch(Pattern pattern, String value, String field) {
        if (value == null || !pattern.matcher(value).matches()) {
            throw new IllegalArgumentException(field + " malformed");
        }
    }

    private static String requirePrintable(String value, String field, int maxLength, boolean allowNewlines) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        if (value.length() > maxLength) {
            throw new IllegalArgumentException(field + " exceeds " + maxLength + " characters");
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean permittedWhitespace = allowNewlines && (c == '\n' || c == '\t');
            if (Character.isISOControl(c) && !permittedWhitespace) {
                throw new IllegalArgumentException(field + " contains control characters");
            }
        }
        return value;
    }

    private static List<String> normalizeScope(List<String> scope) {
        if (scope == null || scope.isEmpty()) {
            throw new IllegalArgumentException("scope must not be empty");
        }
        if (scope.size() > 64) {
            throw new IllegalArgumentException("scope exceeds 64 entries");
        }
        TreeSet<String> sorted = new TreeSet<>();
        for (String entry : scope) {
            if (!Scope.isWellFormed(entry)) {
                throw new IllegalArgumentException("scope entry malformed: " + entry);
            }
            sorted.add(entry);
        }
        return List.copyOf(sorted);
    }

    public Instant issuedAt() {
        return Instant.ofEpochSecond(iat);
    }

    public Instant expiresAt() {
        return Instant.ofEpochSecond(exp);
    }

    public boolean isRoot() {
        return parent == null;
    }

    public String agentName() {
        return agent.substring(0, agent.indexOf('@'));
    }

    public String agentBuildHash() {
        return agent.substring(agent.indexOf('@') + 1);
    }

    public Map<String, Object> toCanonicalMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("agent", agent);
        map.put("ceiling", ceiling.toCanonicalMap());
        map.put("cnf", cnf);
        map.put("exp", exp);
        map.put("hops", hops);
        map.put("iat", iat);
        map.put("kid", kid);
        map.put("mandate", mandate);
        map.put("parent", parent == null ? null : parent.toCanonicalMap());
        map.put("policy_v", policyV);
        map.put("principal", principal);
        map.put("scope", new ArrayList<>(scope));
        map.put("tenant", tenant);
        map.put("v", v);
        map.put("wid", wid);
        return map;
    }
}
