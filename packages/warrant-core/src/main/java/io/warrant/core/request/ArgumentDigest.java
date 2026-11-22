package io.warrant.core.request;

import com.fasterxml.jackson.databind.JsonNode;
import io.warrant.core.crypto.Digests;
import io.warrant.core.json.CanonicalJson;
import io.warrant.core.json.HostileJson;

/**
 * The argument digest is SHA-256 over the canonical JSON of the arguments. It keys the decision cache, binds the
 * request proof, and is the only trace of the arguments that enters the audit chain.
 */
public final class ArgumentDigest {

    private ArgumentDigest() {
    }

    public static String of(JsonNode arguments) {
        return Digests.sha256(canonicalBytes(arguments));
    }

    public static byte[] canonicalBytes(JsonNode arguments) {
        return CanonicalJson.bytes(HostileJson.toCanonicalValue(arguments));
    }
}
