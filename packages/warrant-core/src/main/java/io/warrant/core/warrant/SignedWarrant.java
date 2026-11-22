package io.warrant.core.warrant;

import io.warrant.core.crypto.Base64Url;
import io.warrant.core.crypto.Digests;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

/**
 * One link: {@code wt1.<base64url(canonical claims)>.<base64url(Ed25519 signature)>}.
 * The signature covers {@code "warrant/v1\n" || claims}. The digest is SHA-256 over the claims bytes.
 */
public final class SignedWarrant {

    public static final String PREFIX = "wt1";
    private static final byte[] DOMAIN = "warrant/v1\n".getBytes(StandardCharsets.US_ASCII);

    private final Warrant claims;
    private final byte[] claimsBytes;
    private final byte[] signature;
    private final String digest;

    public SignedWarrant(Warrant claims, byte[] claimsBytes, byte[] signature) {
        this.claims = Objects.requireNonNull(claims, "claims");
        this.claimsBytes = claimsBytes.clone();
        this.signature = signature.clone();
        this.digest = Digests.sha256(this.claimsBytes);
    }

    public static byte[] signingInput(byte[] claimsBytes) {
        byte[] input = new byte[DOMAIN.length + claimsBytes.length];
        System.arraycopy(DOMAIN, 0, input, 0, DOMAIN.length);
        System.arraycopy(claimsBytes, 0, input, DOMAIN.length, claimsBytes.length);
        return input;
    }

    public static SignedWarrant parse(String token) {
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3 || !PREFIX.equals(parts[0])) {
            throw new WarrantCodec.MalformedWarrantException("warrant link must be wt1.<claims>.<signature>");
        }
        byte[] claimsBytes;
        byte[] signature;
        try {
            claimsBytes = Base64Url.decode(parts[1]);
            signature = Base64Url.decode(parts[2]);
        } catch (IllegalArgumentException e) {
            throw new WarrantCodec.MalformedWarrantException("warrant link is not base64url");
        }
        return new SignedWarrant(WarrantCodec.decode(claimsBytes), claimsBytes, signature);
    }

    public Warrant claims() {
        return claims;
    }

    public byte[] claimsBytes() {
        return claimsBytes.clone();
    }

    public byte[] signature() {
        return signature.clone();
    }

    public byte[] signingInput() {
        return signingInput(claimsBytes);
    }

    public String digest() {
        return digest;
    }

    public String token() {
        return PREFIX + "." + Base64Url.encode(claimsBytes) + "." + Base64Url.encode(signature);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof SignedWarrant that
                && Arrays.equals(claimsBytes, that.claimsBytes)
                && Arrays.equals(signature, that.signature);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(claimsBytes) + Arrays.hashCode(signature);
    }

    @Override
    public String toString() {
        return "SignedWarrant[" + claims.wid() + "]";
    }
}
