package io.warrant.cp.admin;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.cp.IntegrationTest;
import io.warrant.cp.identity.UserDirectory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TenantProvisionerTest extends IntegrationTest {

    private static final String WARRANT_KEY =
            "projects/warrant-prod/locations/asia-south1/keyRings/warrant/cryptoKeys/globex-warrant/cryptoKeyVersions/1";
    private static final String AUDIT_KEY =
            "projects/warrant-prod/locations/asia-south1/keyRings/warrant/cryptoKeys/globex-audit/cryptoKeyVersions/1";

    @Autowired
    UserDirectory users;
    @Autowired
    ObjectMapper mapper;
    @TempDir
    Path dir;

    /** Other tests warm signers for every tenant; KMS-backed tenants must not outlive this test. */
    @AfterEach
    void removeProvisionedTenants() {
        for (String table : new String[] {"approvers", "console_users", "key_metadata", "tenants"}) {
            String column = "tenants".equals(table) ? "id" : "tenant_id";
            asDatabaseOwner().update("DELETE FROM " + table + " WHERE " + column
                    + " IN ('globex', 'initech', 'umbrella', 'hooli')");
        }
    }

    private TenantProvisioner provisioner(String json) throws Exception {
        Path file = dir.resolve("provision.json");
        Files.writeString(file, json);
        return new TenantProvisioner(scope, users, mapper, file.toString());
    }

    private String tenant(String id, String warrantKey, String auditKey) {
        return """
                {"tenants":[{"id":"%s","name":"Globex","kms_key_version":"%s","kms_audit_key_version":"%s",
                  "owners":["owner@globex.example"],"approvers":["approver@globex.example"],"auditors":["audit@globex.example"]}]}
                """.formatted(id, warrantKey, auditKey);
    }

    @Test
    void createsTheTenantWithItsKmsKeysAndFirstOwners() throws Exception {
        provisioner(tenant("globex", WARRANT_KEY, AUDIT_KEY)).provision();

        Map<String, Object> row = asDatabaseOwner().queryForMap(
                "SELECT kms_key_uri, kms_audit_key_uri, idp_issuer FROM tenants WHERE id = 'globex'");
        assertThat(row).containsEntry("kms_key_uri", WARRANT_KEY).containsEntry("kms_audit_key_uri", AUDIT_KEY)
                .containsEntry("idp_issuer", "https://accounts.google.com");
        assertThat(users.membership("owner@globex.example")).containsKey("globex");
        assertThat(asDatabaseOwner().queryForObject(
                "SELECT count(*) FROM approvers WHERE tenant_id = 'globex' AND email = 'approver@globex.example'",
                Integer.class)).isEqualTo(1);
    }

    @Test
    void neverModifiesAnExistingTenant() throws Exception {
        provisioner(tenant("initech", WARRANT_KEY, AUDIT_KEY)).provision();
        String otherKey = WARRANT_KEY.replace("/1", "/2");
        provisioner(tenant("initech", otherKey, AUDIT_KEY)).provision();
        assertThat(asDatabaseOwner().queryForObject("SELECT kms_key_uri FROM tenants WHERE id = 'initech'", String.class))
                .isEqualTo(WARRANT_KEY);
    }

    @Test
    void refusesDevelopmentOrMalformedKeys() throws Exception {
        assertThatThrownBy(() -> provisioner(tenant("umbrella", "dev://local", AUDIT_KEY)).provision())
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("Cloud KMS key version");
        assertThatThrownBy(() -> provisioner(tenant("umbrella", WARRANT_KEY.replace("/cryptoKeyVersions/1", ""), AUDIT_KEY)).provision())
                .isInstanceOf(IllegalStateException.class);
        assertThat(asDatabaseOwner().queryForObject("SELECT count(*) FROM tenants WHERE id = 'umbrella'", Integer.class))
                .isZero();
    }

    @Test
    void refusesOneKeyForBothPurposes() throws Exception {
        assertThatThrownBy(() -> provisioner(tenant("hooli", WARRANT_KEY, WARRANT_KEY)).provision())
                .hasMessageContaining("different keys");
    }

    @Test
    void refusesAMalformedTenantId() throws Exception {
        assertThatThrownBy(() -> provisioner(tenant("Bad Tenant; DROP", WARRANT_KEY, AUDIT_KEY)).provision())
                .hasMessageContaining("tenant id");
    }
}
