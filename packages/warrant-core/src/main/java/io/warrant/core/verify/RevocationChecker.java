package io.warrant.core.verify;

@FunctionalInterface
public interface RevocationChecker {
    RevocationChecker NONE_REVOKED = wid -> false;

    boolean isRevoked(String wid);
}
