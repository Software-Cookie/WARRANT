package io.warrant.core.warrant;

import java.util.Collection;
import java.util.regex.Pattern;

/**
 * Permissions are {@code resource.verb}. A scope entry may use {@code *} for either part. Coverage is
 * literal for a query that itself contains a wildcard: {@code vendors.delete} does not cover {@code *.delete}.
 */
public final class Scope {

    private static final Pattern PERMISSION = Pattern.compile("^([a-z0-9_]{1,64}|\\*)\\.([a-z0-9_]{1,32}|\\*)$");

    private Scope() {
    }

    public static boolean isWellFormed(String permission) {
        return permission != null && PERMISSION.matcher(permission).matches();
    }

    public static boolean covers(String entry, String permission) {
        int entryDot = entry.indexOf('.');
        int permissionDot = permission.indexOf('.');
        if (entryDot < 0 || permissionDot < 0) {
            return false;
        }
        return partCovers(entry.substring(0, entryDot), permission.substring(0, permissionDot))
                && partCovers(entry.substring(entryDot + 1), permission.substring(permissionDot + 1));
    }

    private static boolean partCovers(String entryPart, String permissionPart) {
        return entryPart.equals("*") || entryPart.equals(permissionPart);
    }

    public static boolean anyCovers(Collection<String> scope, String permission) {
        for (String entry : scope) {
            if (covers(entry, permission)) {
                return true;
            }
        }
        return false;
    }

    public static boolean isSubset(Collection<String> child, Collection<String> parent) {
        for (String entry : child) {
            if (!anyCovers(parent, entry)) {
                return false;
            }
        }
        return true;
    }
}
