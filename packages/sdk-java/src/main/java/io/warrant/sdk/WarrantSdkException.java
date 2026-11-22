package io.warrant.sdk;

import java.io.Serial;

/** Transport or protocol failure talking to Warrant. A policy refusal is never this: it is a {@link ToolResult}. */
public final class WarrantSdkException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    public WarrantSdkException(String message) {
        super(message);
    }

    public WarrantSdkException(String message, Throwable cause) {
        super(message, cause);
    }
}
