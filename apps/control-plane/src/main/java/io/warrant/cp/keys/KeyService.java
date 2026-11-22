package io.warrant.cp.keys;

import io.warrant.core.crypto.Ed25519;
import io.warrant.core.crypto.Signer;
import io.warrant.core.verify.KeyResolver;
import io.warrant.core.verify.KeyTrustPolicy;
import io.warrant.core.verify.VerificationKey;
import io.warrant.cp.config.WarrantProperties;
import io.warrant.cp.db.TenantScope;
import io.warrant.cp.tenant.Tenant;
import io.warrant.cp.tenant.TenantRepository;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-tenant signing keys (one for warrants, a separate one for audit heads, Bible §24.2). A tenant whose key URI
 * is a KMS key version signs through KMS; {@code dev://} keys are allowed only in development environments.
 * Every public key ever used is recorded in {@code key_metadata} so historical signatures stay verifiable.
 */
@Service
public class KeyService implements KeyResolver {

    public static final String DEV_KEY_URI = "dev://local";

    private final WarrantProperties properties;
    private final TenantRepository tenants;
    private final TenantScope scope;
    private final KmsClient kms;
    private final DevelopmentKeyFiles devKeys;
    private final Map<String, Signer> signers = new ConcurrentHashMap<>();
    private final Map<String, VerificationKey> verificationKeys = new ConcurrentHashMap<>();

    public KeyService(WarrantProperties properties, TenantRepository tenants, TenantScope scope, KmsClient kms) {
        this.properties = properties;
        this.tenants = tenants;
        this.scope = scope;
        this.kms = kms;
        this.devKeys = new DevelopmentKeyFiles(Path.of(properties.keys().devKeysDir()));
    }

    public Signer warrantSigner(String tenantId) {
        return signer(tenantId, VerificationKey.KeyPurpose.WARRANT);
    }

    public Signer auditSigner(String tenantId) {
        return signer(tenantId, VerificationKey.KeyPurpose.AUDIT);
    }

    public KeyTrustPolicy trustPolicy() {
        return KeyTrustPolicy.forEnvironment(properties.env());
    }

    private Signer signer(String tenantId, VerificationKey.KeyPurpose purpose) {
        return signers.computeIfAbsent(tenantId + "/" + purpose, k -> createSigner(tenantId, purpose));
    }

    private Signer createSigner(String tenantId, VerificationKey.KeyPurpose purpose) {
        Tenant tenant = tenants.find(tenantId).orElseThrow(() -> new IllegalArgumentException("unknown tenant"));
        String uri = purpose == VerificationKey.KeyPurpose.WARRANT ? tenant.kmsKeyUri() : tenant.kmsAuditKeyUri();
        Signer signer;
        if (KmsClient.isKeyVersionName(uri)) {
            signer = new KmsSigner(kms, uri);
        } else if (DEV_KEY_URI.equals(uri) || uri == null || uri.isBlank()) {
            if (!properties.isDevelopment()) {
                throw new IllegalStateException("tenant " + tenantId + " has no KMS " + purpose + " key in " + properties.env());
            }
            signer = devKeys.signer(tenantId, purpose.name().toLowerCase(java.util.Locale.ROOT));
        } else {
            throw new IllegalStateException("unsupported key URI for tenant " + tenantId);
        }
        record(tenantId, purpose, signer);
        return signer;
    }

    private void record(String tenantId, VerificationKey.KeyPurpose purpose, Signer signer) {
        String pem = Ed25519.toPem(signer.publicKey());
        String source = signer instanceof KmsSigner ? "kms" : "development";
        scope.runVoid(tenantId, jdbc -> jdbc.update("""
                INSERT INTO key_metadata (tenant_id, kid, purpose, algorithm, public_pem, source)
                VALUES (?, ?, ?, 'Ed25519', ?, ?) ON CONFLICT (tenant_id, kid) DO NOTHING
                """, tenantId, signer.kid(), purpose.name().toLowerCase(java.util.Locale.ROOT), pem, source));
        verificationKeys.put(signer.kid(), new VerificationKey(signer.kid(), tenantId, purpose, signer.publicKey()));
    }

    public byte[] envelopeMasterKey() {
        if (!properties.isDevelopment()) {
            throw new IllegalStateException("software envelope keys are development-only");
        }
        return devKeys.envelopeMasterKey();
    }

    /** All verification keys, warming signers for every tenant so a fresh process can verify immediately. */
    public List<VerificationKey> verificationKeys() {
        for (Tenant tenant : tenants.all()) {
            loadRecordedKeys(tenant.id());
            warrantSigner(tenant.id());
            auditSigner(tenant.id());
        }
        return new ArrayList<>(verificationKeys.values());
    }

    private void loadRecordedKeys(String tenantId) {
        scope.runVoid(tenantId, jdbc -> jdbc.query(
                "SELECT kid, purpose, public_pem FROM key_metadata WHERE tenant_id = ?",
                rs -> {
                    PublicKey key = Ed25519.publicKeyFromPem(rs.getString("public_pem"));
                    VerificationKey.KeyPurpose purpose = VerificationKey.KeyPurpose.valueOf(
                            rs.getString("purpose").toUpperCase(java.util.Locale.ROOT));
                    verificationKeys.putIfAbsent(rs.getString("kid"),
                            new VerificationKey(rs.getString("kid"), tenantId, purpose, key));
                }, tenantId));
    }

    @Override
    public Optional<VerificationKey> resolve(String kid) {
        VerificationKey key = verificationKeys.get(kid);
        if (key == null) {
            verificationKeys();
            key = verificationKeys.get(kid);
        }
        return Optional.ofNullable(key);
    }
}
