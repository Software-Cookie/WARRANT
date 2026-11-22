package io.warrant.cp.keys;

import io.warrant.core.crypto.Digests;
import io.warrant.core.crypto.Ed25519;
import io.warrant.core.crypto.Signer;

import java.security.PublicKey;

/** Signs through Cloud KMS ({@code EC_SIGN_ED25519}). The kid is derived from the public key and never starts with dev-. */
public final class KmsSigner implements Signer {

    private final KmsClient kms;
    private final String keyVersionName;
    private final PublicKey publicKey;
    private final String kid;

    public KmsSigner(KmsClient kms, String keyVersionName) {
        this.kms = kms;
        this.keyVersionName = keyVersionName;
        this.publicKey = Ed25519.publicKeyFromPem(kms.publicKeyPem(keyVersionName));
        this.kid = "kms-" + Digests.sha256(Ed25519.rawPublicKey(publicKey)).substring(7, 23);
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
        return kms.asymmetricSign(keyVersionName, message);
    }

    @Override
    public String toString() {
        return "KmsSigner[" + kid + "]";
    }
}
