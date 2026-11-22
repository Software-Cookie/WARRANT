package io.warrant.cp.identity;

import io.warrant.cp.db.TenantScope;
import org.springframework.stereotype.Repository;

import java.sql.Array;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

@Repository
public class UserDirectory {

    private final TenantScope scope;

    public UserDirectory(TenantScope scope) {
        this.scope = scope;
    }

    /** Tenants the email belongs to, with that tenant's roles. A cross-tenant read permitted only for login. */
    public Map<String, Set<Role>> membership(String email) {
        String normalized = normalize(email);
        return scope.system(jdbc -> {
            Map<String, Set<Role>> result = new TreeMap<>();
            jdbc.query("SELECT tenant_id, roles FROM console_users WHERE email = ?",
                    rs -> {
                        result.put(rs.getString("tenant_id"), roles(rs.getArray("roles")));
                    }, normalized);
            return result;
        });
    }

    public Optional<Set<Role>> roles(String tenant, String email) {
        return scope.run(tenant, jdbc -> jdbc.query("SELECT roles FROM console_users WHERE tenant_id = ? AND email = ?",
                (rs, row) -> roles(rs.getArray("roles")), tenant, normalize(email)).stream().findFirst());
    }

    public List<Map<String, Object>> list(String tenant) {
        return scope.run(tenant, jdbc -> jdbc.queryForList(
                "SELECT email, roles::text AS roles, created_at FROM console_users WHERE tenant_id = ? ORDER BY email", tenant));
    }

    public void upsert(String tenant, String email, Set<Role> roles) {
        if (roles.contains(Role.AUDITOR) && roles.contains(Role.APPROVER)) {
            throw new IllegalArgumentException("an auditor cannot hold approval rights");
        }
        String[] names = roles.stream().map(Role::dbName).sorted().toArray(String[]::new);
        scope.runVoid(tenant, jdbc -> jdbc.update("""
                INSERT INTO console_users (tenant_id, email, roles) VALUES (?, ?, ?)
                ON CONFLICT (tenant_id, email) DO UPDATE SET roles = EXCLUDED.roles
                """, ps -> {
            ps.setString(1, tenant);
            ps.setString(2, normalize(email));
            ps.setArray(3, ps.getConnection().createArrayOf("text", names));
        }));
    }

    static String normalize(String email) {
        if (email == null || email.isBlank() || email.length() > 320 || !email.contains("@")) {
            throw new IllegalArgumentException("invalid email");
        }
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private static Set<Role> roles(Array array) throws java.sql.SQLException {
        Set<Role> roles = EnumSet.noneOf(Role.class);
        for (Object value : (Object[]) array.getArray()) {
            roles.add(Role.fromDb(value.toString()));
        }
        return roles;
    }
}
