package io.warrant.sdk;

import io.warrant.core.crypto.Base64Url;
import io.warrant.core.crypto.Ed25519;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

/**
 * The agent's proof-of-possession key. The public half goes into the warrant's {@code cnf}; the private half signs
 * every request and never leaves the agent. Load it from a file the agent's runtime mounts (a Secret Manager volume
 * in production), never from source.
 */
public final class AgentKey {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    private AgentKey(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
        this.publicKey = Objects.requireNonNull(publicKey, "publicKey");
    }

    public static AgentKey generate() {
        KeyPair pair = Ed25519.generate();
        return new AgentKey(pair.getPrivate(), pair.getPublic());
    }

    public static AgentKey of(KeyPair pair) {
        Objects.requireNonNull(pair, "pair");
        return new AgentKey(pair.getPrivate(), pair.getPublic());
    }

    /** Reads a PKCS#8 private key PEM and its X.509 public key PEM. */
    public static AgentKey fromPemFiles(Path privateKeyPem, Path publicKeyPem) {
        try {
            return new AgentKey(Ed25519.privateKeyFromPem(Files.readString(privateKeyPem)),
                    Ed25519.publicKeyFromPem(Files.readString(publicKeyPem)));
        } catch (IOException e) {
            throw new UncheckedIOException("agent key unreadable", e);
        }
    }

    /** The value for the warrant's {@code cnf} claim: base64url of the raw 32-byte public key. */
    public String confirmation() {
        return Base64Url.encode(Ed25519.rawPublicKey(publicKey));
    }

    public void writePemFiles(Path privateKeyPem, Path publicKeyPem) {
        try {
            Files.writeString(privateKeyPem, Ed25519.toPem(privateKey));
            Files.writeString(publicKeyPem, Ed25519.toPem(publicKey));
        } catch (IOException e) {
            throw new UncheckedIOException("agent key not writable", e);
        }
    }

    PrivateKey privateKey() {
        return privateKey;
    }

    @Override
    public String toString() {
        return "AgentKey[cnf=" + confirmation() + "]";
    }
}
