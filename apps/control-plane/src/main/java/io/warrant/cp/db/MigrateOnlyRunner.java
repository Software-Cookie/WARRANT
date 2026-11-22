package io.warrant.cp.db;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.stereotype.Component;

/**
 * Migration job mode ({@code WARRANT_MIGRATE_ONLY=true}): Flyway has run during startup as the schema-owning
 * identity, tenant provisioning has run on ready, and the process exits. The long-running control plane runs with
 * {@code WARRANT_DB_MIGRATE=false} under an identity that can only assume warrant_app.
 */
@Component
@ConditionalOnProperty(name = "warrant.migrate-only", havingValue = "true")
public class MigrateOnlyRunner implements ApplicationRunner {

    private static final Logger LOG = LoggerFactory.getLogger(MigrateOnlyRunner.class);

    private final ConfigurableApplicationContext context;

    public MigrateOnlyRunner(ConfigurableApplicationContext context) {
        this.context = context;
    }

    @Override
    public void run(ApplicationArguments args) {
        LOG.info("migrations applied; migrate-only mode exits");
        Thread exit = new Thread(() -> System.exit(SpringApplication.exit(context, () -> 0)), "migrate-only-exit");
        exit.start();
    }
}
