package io.warrant.cp.admin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.cp.db.TenantScope;
import io.warrant.cp.identity.Role;
import io.warrant.cp.identity.UserDirectory;
import io.warrant.cp.keys.KmsClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.EnumSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Production tenant provisioning. Creates each tenant listed in {@code WARRANT_PROVISION_FILE} once, with its Cloud
 * KMS signing key versions and its first owners, so the first owner exists before any API call can be authenticated.
 *
 * <p>It never modifies an existing tenant (later changes go through the admin API and its two-person rules), and it
 * accepts only real Cloud KMS key version names, distinct for warrant and audit signing.
 */
@Component
public class TenantProvisioner {

    private static final Logger LOG = LoggerFactory.getLogger(TenantProvisioner.class);
    private static final Pattern TENANT_ID = Pattern.compile("^[a-z][a-z0-9-]{1,39}$");
    private static final Pattern EMAIL = Pattern.compile("^[^@\\s]{1,64}@[^@\\s]{1,190}$");

    private final TenantScope scope;
    private final UserDirectory users;
    private final ObjectMapper mapper;
    private final String file;

    public TenantProvisioner(TenantScope scope, UserDirectory users, ObjectMapper mapper,
                             @Value("${WARRANT_PROVISION_FILE:}") String file) {
        this.scope = scope;
        this.users = users;
        this.mapper = mapper;
        this.file = file;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void provision() {
        if (file == null || file.isBlank()) {
            return;
        }
        JsonNode root;
        try {
            root = mapper.readTree(Files.readString(Path.of(file)));
        } catch (IOException e) {
            throw new IllegalStateException("provisioning file unreadable: " + file, e);
        }
        for (JsonNode tenant : root.path("tenants")) {
            provisionTenant(tenant);
        }
    }

    private void provisionTenant(JsonNode tenant) {
        String id = requireMatch(tenant.path("id").asText(""), TENANT_ID, "tenant id");
        String warrantKey = requireKeyVersion(tenant.path("kms_key_version").asText(""), id, "kms_key_version");
        String auditKey = requireKeyVersion(tenant.path("kms_audit_key_version").asText(""), id, "kms_audit_key_version");
        String issuer = tenant.path("idp_issuer").asText("https://accounts.google.com");
        if (!issuer.startsWith("https://")) {
            throw new IllegalStateException("tenant " + id + ": idp_issuer must be an https issuer URL");
        }
        if (warrantKey.equals(auditKey)) {
            throw new IllegalStateException("tenant " + id + ": warrant and audit signing must use different keys");
        }
        int created = scope.run(id, jdbc -> jdbc.update("""
                INSERT INTO tenants (id, name, region, kms_key_uri, kms_audit_key_uri, idp_issuer, escalation_ttl_seconds,
                                     settings)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?::jsonb)
                ON CONFLICT (id) DO NOTHING
                """, id, tenant.path("name").asText(id), tenant.path("region").asText("asia-south1"), warrantKey, auditKey,
                issuer,
                tenant.path("escalation_ttl_seconds").asInt(300), tenant.path("settings").isObject()
                        ? tenant.path("settings").toString() : "{}"));
        if (created == 0) {
            LOG.info("tenant {} already exists; provisioning leaves it unchanged", id);
            return;
        }
        for (JsonNode owner : tenant.path("owners")) {
            String email = requireMatch(owner.asText(""), EMAIL, "owner email");
            users.upsert(id, email, EnumSet.of(Role.OWNER, Role.SECURITY_ADMIN));
        }
        for (JsonNode approver : tenant.path("approvers")) {
            String email = requireMatch(approver.asText(""), EMAIL, "approver email");
            Set<Role> roles = EnumSet.of(Role.APPROVER);
            users.upsert(id, email, roles);
            scope.runVoid(id, jdbc -> jdbc.update(
                    "INSERT INTO approvers (tenant_id, email) VALUES (?, ?) ON CONFLICT DO NOTHING", id, email));
        }
        for (JsonNode auditor : tenant.path("auditors")) {
            users.upsert(id, requireMatch(auditor.asText(""), EMAIL, "auditor email"), EnumSet.of(Role.AUDITOR));
        }
        LOG.info("tenant {} provisioned with Cloud KMS signing keys", id);
    }

    private static String requireKeyVersion(String value, String tenant, String field) {
        if (!KmsClient.isKeyVersionName(value)) {
            throw new IllegalStateException("tenant " + tenant + ": " + field
                    + " must be a Cloud KMS key version (projects/…/cryptoKeyVersions/N)");
        }
        return value;
    }

    private static String requireMatch(String value, Pattern pattern, String what) {
        if (!pattern.matcher(value).matches()) {
            throw new IllegalStateException("invalid " + what + " in provisioning file");
        }
        return value;
    }
}
