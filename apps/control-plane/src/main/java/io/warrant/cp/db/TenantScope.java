package io.warrant.cp.db;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Every database access runs inside a transaction whose row-level-security context names exactly one tenant.
 * {@link #system} exists only for the two cross-tenant reads the schema permits (listing tenants, resolving a
 * console user's tenants) and is used by background jobs and login, never by request handlers acting on data.
 */
@Component
public class TenantScope {

    private static final Pattern TENANT = Pattern.compile("^[a-z0-9][a-z0-9-]{1,62}$");

    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;

    public TenantScope(JdbcTemplate jdbc, PlatformTransactionManager transactionManager) {
        this.jdbc = jdbc;
        this.transactions = new TransactionTemplate(transactionManager);
    }

    public <T> T run(String tenant, Function<JdbcTemplate, T> work) {
        if (tenant == null || !TENANT.matcher(tenant).matches()) {
            throw new IllegalArgumentException("invalid tenant id");
        }
        return transactions.execute(status -> {
            jdbc.queryForObject("SELECT set_config('warrant.tenant', ?, true)", String.class, tenant);
            return work.apply(jdbc);
        });
    }

    public void runVoid(String tenant, java.util.function.Consumer<JdbcTemplate> work) {
        run(tenant, j -> {
            work.accept(j);
            return null;
        });
    }

    public <T> T system(Function<JdbcTemplate, T> work) {
        return transactions.execute(status -> {
            jdbc.queryForObject("SELECT set_config('warrant.system', 'on', true)", String.class);
            return work.apply(jdbc);
        });
    }
}
