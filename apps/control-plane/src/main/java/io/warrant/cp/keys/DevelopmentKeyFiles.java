package io.warrant.cp.keys;

import io.warrant.core.crypto.Digests;
import io.warrant.core.crypto.Ed25519;
import io.warrant.core.crypto.InMemorySigner;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.regex.Pattern;

/**
 * Development-only key material under a git-ignored directory referenced by {@code WARRANT_DEV_KEYS_DIR}. Created on
 * first use. Every signer it produces has a {@code dev-} kid, which production trust policy rejects.
 */
public final class DevelopmentKeyFiles {

    private static final Pattern NAME = Pattern.compile("^[a-z0-9][a-z0-9-]{1,62}$");

    private final Path directory;

    public DevelopmentKeyFiles(Path directory) {
        this.directory = directory.toAbsolutePath().normalize();
    }

    public InMemorySigner signer(String tenant, String purpose) {
        if (!NAME.matcher(tenant).matches() || !NAME.matcher(purpose).matches()) {
            throw new IllegalArgumentException("invalid key name");
        }
        Path file = directory.resolve(tenant + "-" + purpose + ".pem");
        try {
            PrivateKey privateKey;
            java.security.PublicKey publicKey;
            if (Files.exists(file)) {
                String pem = Files.readString(file, StandardCharsets.US_ASCII);
                privateKey = Ed25519.privateKeyFromPem(pem);
                publicKey = Ed25519.publicKeyFromPem(pem);
            } else {
                KeyPair pair = Ed25519.generate();
                privateKey = pair.getPrivate();
                publicKey = pair.getPublic();
                writeOwnerOnly(file, Ed25519.toPem(privateKey) + Ed25519.toPem(publicKey));
            }
            String kid = "dev-" + tenant + "-" + purpose + "-"
                    + Digests.sha256(Ed25519.rawPublicKey(publicKey)).substring(7, 19);
            return new InMemorySigner(kid, privateKey, publicKey);
        } catch (IOException e) {
            throw new IllegalStateException("development key directory not usable: " + e.getClass().getSimpleName());
        }
    }

    public byte[] envelopeMasterKey() {
        Path file = directory.resolve("envelope.key");
        try {
            if (Files.exists(file)) {
                byte[] key = java.util.Base64.getDecoder().decode(Files.readString(file, StandardCharsets.US_ASCII).strip());
                if (key.length != 32) {
                    throw new IllegalStateException("envelope.key must hold 32 bytes");
                }
                return key;
            }
            byte[] key = new byte[32];
            new SecureRandom().nextBytes(key);
            writeOwnerOnly(file, java.util.Base64.getEncoder().encodeToString(key) + "\n");
            return key;
        } catch (IOException e) {
            throw new IllegalStateException("development key directory not usable: " + e.getClass().getSimpleName());
        }
    }

    private void writeOwnerOnly(Path file, String content) throws IOException {
        Files.createDirectories(directory);
        Path temp = Files.createTempFile(directory, ".key", ".tmp");
        Files.writeString(temp, content, StandardCharsets.US_ASCII);
        try {
            Files.setPosixFilePermissions(temp, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException e) {
            temp.toFile().setReadable(false, false);
            temp.toFile().setReadable(true, true);
        }
        try {
            Files.move(temp, file, java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        } catch (java.nio.file.FileAlreadyExistsException e) {
            Files.deleteIfExists(temp);
        }
    }
}
