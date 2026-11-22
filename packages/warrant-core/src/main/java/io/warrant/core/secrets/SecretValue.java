package io.warrant.core.secrets;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * A secret held in memory for the duration of a request. {@link #toString()} never reveals it, so a careless
 * log statement or exception message cannot leak it. Callers that are done with it should {@link #destroy()} it.
 */
public final class SecretValue implements AutoCloseable {

    private final byte[] value;
    private volatile boolean destroyed;

    public SecretValue(byte[] value) {
        this.value = value.clone();
    }

    public String reveal() {
        if (destroyed) {
            throw new IllegalStateException("secret already destroyed");
        }
        return new String(value, StandardCharsets.UTF_8).strip();
    }

    public void destroy() {
        Arrays.fill(value, (byte) 0);
        destroyed = true;
    }

    @Override
    public void close() {
        destroy();
    }

    @Override
    public String toString() {
        return "SecretValue[redacted]";
    }
}
