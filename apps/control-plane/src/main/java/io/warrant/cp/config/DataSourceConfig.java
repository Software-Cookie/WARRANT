package io.warrant.cp.config;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.boot.autoconfigure.flyway.FlywayDataSource;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import javax.sql.DataSource;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Database access uses IAM authentication: in Google Cloud the Cloud SQL connector exchanges the workload identity
 * for a short-lived token, so no password exists anywhere. Locally the compose Postgres trusts loopback.
 *
 * <p>The application pool assumes the {@code warrant_app} role on every connection so row-level security applies;
 * migrations use a separate pool that runs as the schema owner.
 */
@Configuration
public class DataSourceConfig {

    @Bean
    @Primary
    public DataSource dataSource(WarrantProperties properties) {
        HikariConfig config = base(properties, "warrant-app");
        config.setConnectionInitSql("SET ROLE warrant_app");
        config.setMaximumPoolSize(properties.db().poolSize());
        return lazily(config);
    }

    @Bean
    @FlywayDataSource
    @ConditionalOnProperty(name = "spring.flyway.enabled", havingValue = "true", matchIfMissing = true)
    public DataSource migrationDataSource(WarrantProperties properties) {
        HikariConfig config = base(properties, "warrant-migrate");
        config.setMaximumPoolSize(2);
        config.setMinimumIdle(0);
        return lazily(config);
    }

    /** The pool opens on first use, after migrations have created the warrant_app role. */
    private static HikariDataSource lazily(HikariConfig config) {
        HikariDataSource dataSource = new HikariDataSource();
        config.copyStateTo(dataSource);
        return dataSource;
    }

    static HikariConfig base(WarrantProperties properties, String poolName) {
        WarrantProperties.Db db = properties.db();
        HikariConfig config = new HikariConfig();
        config.setPoolName(poolName);
        if (db.instance() != null && !db.instance().isBlank()) {
            if (db.iamUser() == null || db.iamUser().isBlank()) {
                throw new IllegalStateException("WARRANT_DB_IAM_USER is required with WARRANT_DB_INSTANCE");
            }
            config.setJdbcUrl("jdbc:postgresql:///" + encode(db.name())
                    + "?cloudSqlInstance=" + encode(db.instance())
                    + "&socketFactory=com.google.cloud.sql.postgres.SocketFactory"
                    + "&enableIamAuth=true&sslmode=disable");
            config.setUsername(db.iamUser());
        } else {
            if (!properties.isDevelopment()) {
                throw new IllegalStateException("non-development environments must use Cloud SQL IAM authentication");
            }
            config.setJdbcUrl("jdbc:postgresql://" + db.host() + ":" + db.port() + "/" + encode(db.name()));
            config.setUsername(db.localUser());
        }
        config.setConnectionTimeout(3000);
        config.setValidationTimeout(1000);
        config.addDataSourceProperty("ApplicationName", poolName);
        return config;
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
