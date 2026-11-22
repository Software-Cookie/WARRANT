package io.warrant.core.crypto;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

/**
 * Software signer. Only for development, tests and the local profile; its kid must carry the {@code dev-}
 * prefix so production trust policy rejects anything it signs.
 */
public final class InMemorySigner implements Signer {

    private final String kid;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    public InMemorySigner(String kid, PrivateKey privateKey, PublicKey publicKey) {
        this.kid = Objects.requireNonNull(kid, "kid");
        if (!kid.startsWith("dev-")) {
            throw new IllegalArgumentException("software signing keys must use a dev- kid");
        }
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
        this.publicKey = Objects.requireNonNull(publicKey, "publicKey");
    }

    public static InMemorySigner generate(String kid) {
        KeyPair pair = Ed25519.generate();
        return new InMemorySigner(kid, pair.getPrivate(), pair.getPublic());
    }

    @Override
    public String kid() {
        return kid;
    }

    @Override
    public PublicKey publicKey() {
        return publicKey;
    }

    @Override
    public byte[] sign(byte[] message) {
        return Ed25519.sign(privateKey, message);
    }

    @Override
    public String toString() {
        return "InMemorySigner[" + kid + "]";
    }
}
