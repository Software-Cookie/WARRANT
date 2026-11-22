package io.warrant.core.crypto;

import java.security.PublicKey;

/**
 * A signing capability. Production implementations delegate to Cloud KMS so the private key never enters
 * application memory; the local implementation holds a development key whose kid starts with {@code dev-}.
 */
public interface Signer {

    String kid();

    PublicKey publicKey();

    byte[] sign(byte[] message);
}
