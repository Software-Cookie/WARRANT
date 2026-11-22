package io.warrant.cp.identity;

import java.util.Locale;

/**
 * Console roles (Bible §30). The person who writes policy should not be the one who approves exceptions to it, and
 * an auditor is read-only everywhere — the schema forbids granting auditor and approver together.
 */
public enum Role {
    OWNER,
    SECURITY_ADMIN,
    APPROVER,
    DEVELOPER,
    AUDITOR;

    public String dbName() {
        return name().toLowerCase(Locale.ROOT);
    }

    public static Role fromDb(String value) {
        return valueOf(value.toUpperCase(Locale.ROOT));
    }
}
