package io.warrant.cp;

import io.warrant.cp.db.TenantScope;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import javax.sql.DataSource;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Base for tests touching persistence or caching: real PostgreSQL 16 and Redis 7.2 in containers, never mocks.
 * Containers are started once per JVM and shared.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public abstract class IntegrationTest {

    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(DockerImageName.parse("postgres:16-alpine"))
            .withEnv("POSTGRES_HOST_AUTH_METHOD", "trust");
    static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse("redis:7.2-alpine"))
            .withExposedPorts(6379);
    static final Path KEYS;

    static {
        POSTGRES.start();
        REDIS.start();
        try {
            KEYS = Files.createTempDirectory("warrant-test-keys");
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @TempDir
    static Path unused;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("warrant.env", () -> "test");
        registry.add("warrant.db.host", POSTGRES::getHost);
        registry.add("warrant.db.port", () -> POSTGRES.getMappedPort(5432));
        registry.add("warrant.db.name", POSTGRES::getDatabaseName);
        registry.add("warrant.db.local-user", POSTGRES::getUsername);
        registry.add("warrant.keys.dev-keys-dir", KEYS::toString);
        registry.add("warrant.secrets.local-dir", KEYS::toString);
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
    }

    @Autowired
    protected TenantScope scope;

    @Autowired
    @Qualifier("migrationDataSource")
    protected DataSource superuser;

    /** A connection with the powers of an attacker who fully controls the database. */
    protected JdbcTemplate asDatabaseOwner() {
        return new JdbcTemplate(superuser);
    }

    protected void createTenant(String id) {
        scope.runVoid(id, jdbc -> jdbc.update("""
                INSERT INTO tenants (id, name, region, kms_key_uri, kms_audit_key_uri, active_policy_v)
                VALUES (?, ?, 'local', 'dev://local', 'dev://local', NULL) ON CONFLICT (id) DO NOTHING
                """, id, id));
    }
}
