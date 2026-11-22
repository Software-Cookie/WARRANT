package io.warrant.cp;

import io.warrant.core.crypto.Base64Url;
import io.warrant.core.crypto.Ed25519;
import io.warrant.cp.identity.Role;
import io.warrant.cp.identity.UserDirectory;
import io.warrant.cp.policy.PolicyService;
import io.warrant.cp.warrant.Agent;
import io.warrant.cp.warrant.AgentDirectory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.EnumSet;
import java.util.List;

/** Seeds a tenant the way the demo does: users, the vendor-hygiene agent, and the example vendor policy. */
public final class Fixtures {

    public static final String BUILD = "sha256:" + "4f1c".repeat(16);

    private Fixtures() {
    }

    public static void seedTenant(IntegrationTest test, String tenant, UserDirectory users, AgentDirectory agents,
                                  PolicyService policies) {
        test.createTenant(tenant);
        users.upsert(tenant, "r.menon@acme.com", EnumSet.of(Role.APPROVER));
        users.upsert(tenant, "priya@acme.com", EnumSet.of(Role.SECURITY_ADMIN));
        users.upsert(tenant, "meera@acme.com", EnumSet.of(Role.DEVELOPER));
        users.upsert(tenant, "daniel@acme.com", EnumSet.of(Role.AUDITOR));
        agents.register(new Agent(tenant, "vendor-hygiene", BUILD,
                List.of("vendors.read", "vendors.archive", "vendors.delete", "payment_holds.delete"), "arun@acme.com", null));
        policies.publish(tenant, repositoryFile("policies/examples/vendors.policy"), null, "priya@acme.com");
    }

    public static String repositoryFile(String relative) {
        for (Path dir = Path.of("").toAbsolutePath(); dir != null; dir = dir.getParent()) {
            Path candidate = dir.resolve(relative);
            if (Files.exists(candidate)) {
                try {
                    return Files.readString(candidate, StandardCharsets.UTF_8);
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            }
        }
        throw new IllegalStateException(relative + " not found");
    }

    public static KeyPair agentKey() {
        return Ed25519.generate();
    }

    public static String cnf(KeyPair key) {
        return Base64Url.encode(Ed25519.rawPublicKey(key.getPublic()));
    }
}
