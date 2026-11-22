package io.warrant.core.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/** Ed25519 helpers on top of the JDK provider. No third-party crypto. */
public final class Ed25519 {

    public static final int RAW_PUBLIC_KEY_LENGTH = 32;
    public static final int SIGNATURE_LENGTH = 64;

    // DER prefix of an X.509 SubjectPublicKeyInfo for Ed25519 (RFC 8410).
    private static final byte[] X509_PREFIX = {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    };

    private Ed25519() {
    }

    public static KeyPair generate() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 unavailable in this JVM", e);
        }
    }

    public static byte[] sign(PrivateKey key, byte[] message) {
        try {
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(key);
            signer.update(message);
            return signer.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 signing failed", e);
        }
    }

    public static boolean verify(PublicKey key, byte[] message, byte[] signature) {
        if (signature == null || signature.length != SIGNATURE_LENGTH) {
            return false;
        }
        try {
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(key);
            verifier.update(message);
            return verifier.verify(signature);
        } catch (SignatureException | InvalidKeyException e) {
            return false;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 unavailable in this JVM", e);
        }
    }

    public static byte[] rawPublicKey(PublicKey key) {
        byte[] encoded = key.getEncoded();
        if (encoded.length != X509_PREFIX.length + RAW_PUBLIC_KEY_LENGTH
                || !Arrays.equals(Arrays.copyOf(encoded, X509_PREFIX.length), X509_PREFIX)) {
            throw new IllegalArgumentException("not an Ed25519 public key");
        }
        return Arrays.copyOfRange(encoded, X509_PREFIX.length, encoded.length);
    }

    public static PublicKey publicKeyFromRaw(byte[] raw) {
        if (raw == null || raw.length != RAW_PUBLIC_KEY_LENGTH) {
            throw new IllegalArgumentException("Ed25519 public key must be 32 bytes");
        }
        byte[] encoded = new byte[X509_PREFIX.length + RAW_PUBLIC_KEY_LENGTH];
        System.arraycopy(X509_PREFIX, 0, encoded, 0, X509_PREFIX.length);
        System.arraycopy(raw, 0, encoded, X509_PREFIX.length, RAW_PUBLIC_KEY_LENGTH);
        return publicKeyFromDer(encoded);
    }

    public static PublicKey publicKeyFromDer(byte[] der) {
        try {
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("invalid Ed25519 public key encoding", e);
        }
    }

    public static PublicKey publicKeyFromPem(String pem) {
        return publicKeyFromDer(pemBody(pem, "PUBLIC KEY"));
    }

    public static PrivateKey privateKeyFromPem(String pem) {
        try {
            return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(pemBody(pem, "PRIVATE KEY")));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("invalid Ed25519 private key encoding", e);
        }
    }

    public static String toPem(PublicKey key) {
        return pem("PUBLIC KEY", key.getEncoded());
    }

    public static String toPem(PrivateKey key) {
        return pem("PRIVATE KEY", key.getEncoded());
    }

    private static String pem(String label, byte[] der) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
        return "-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----\n";
    }

    private static byte[] pemBody(String pem, String label) {
        String begin = "-----BEGIN " + label + "-----";
        String end = "-----END " + label + "-----";
        int start = pem.indexOf(begin);
        int stop = pem.indexOf(end);
        if (start < 0 || stop < start) {
            throw new IllegalArgumentException("PEM block '" + label + "' not found");
        }
        String body = pem.substring(start + begin.length(), stop).replaceAll("\\s", "");
        return Base64.getDecoder().decode(body);
    }
}
