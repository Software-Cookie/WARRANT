package io.warrant.core.warrant;

import io.warrant.core.crypto.Signer;

/** Encodes claims canonically and signs them. Does not check policy; callers enforce issuance rules first. */
public final class WarrantMinter {

    private WarrantMinter() {
    }

    public static SignedWarrant mint(Warrant claims, Signer signer) {
        if (!claims.kid().equals(signer.kid())) {
            throw new IllegalArgumentException("claims.kid does not match the signer");
        }
        byte[] claimsBytes = WarrantCodec.encode(claims);
        byte[] signature = signer.sign(SignedWarrant.signingInput(claimsBytes));
        return new SignedWarrant(claims, claimsBytes, signature);
    }
}
