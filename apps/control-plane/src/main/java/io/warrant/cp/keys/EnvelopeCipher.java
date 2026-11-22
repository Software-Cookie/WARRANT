package io.warrant.cp.keys;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Envelope encryption for the only customer data Warrant ever holds at rest: parked tool-call arguments and released
 * results. Each blob gets a fresh AES-256-GCM data key, wrapped by the key-encryption key (Cloud KMS in production).
 * The context string (tenant, purpose, record id) is authenticated, so a blob cannot be moved to another record.
 *
 * <p>Format: {@code 0x01 | u16 wrappedLength | wrappedKey | 12-byte nonce | ciphertext+tag}.
 */
public final class EnvelopeCipher {

    private static final byte VERSION = 1;
    private static final int NONCE_LENGTH = 12;
    private static final int TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final KeyEncryptionKey kek;

    public EnvelopeCipher(KeyEncryptionKey kek) {
        this.kek = kek;
    }

    public interface KeyEncryptionKey {
        byte[] wrap(byte[] dataKey, byte[] context);

        byte[] unwrap(byte[] wrapped, byte[] context);
    }

    public byte[] seal(byte[] plaintext, String context) {
        byte[] aad = context.getBytes(StandardCharsets.UTF_8);
        byte[] dataKey = new byte[32];
        RANDOM.nextBytes(dataKey);
        try {
            byte[] wrapped = kek.wrap(dataKey, aad);
            byte[] nonce = new byte[NONCE_LENGTH];
            RANDOM.nextBytes(nonce);
            byte[] ciphertext = aesGcm(Cipher.ENCRYPT_MODE, dataKey, nonce, aad, plaintext);
            return ByteBuffer.allocate(1 + 2 + wrapped.length + NONCE_LENGTH + ciphertext.length)
                    .put(VERSION).putShort((short) wrapped.length).put(wrapped).put(nonce).put(ciphertext).array();
        } finally {
            Arrays.fill(dataKey, (byte) 0);
        }
    }

    public byte[] open(byte[] sealed, String context) {
        byte[] aad = context.getBytes(StandardCharsets.UTF_8);
        ByteBuffer buffer = ByteBuffer.wrap(sealed);
        if (buffer.remaining() < 3 || buffer.get() != VERSION) {
            throw new IllegalArgumentException("unsupported envelope format");
        }
        int wrappedLength = Short.toUnsignedInt(buffer.getShort());
        if (buffer.remaining() < wrappedLength + NONCE_LENGTH) {
            throw new IllegalArgumentException("truncated envelope");
        }
        byte[] wrapped = new byte[wrappedLength];
        buffer.get(wrapped);
        byte[] nonce = new byte[NONCE_LENGTH];
        buffer.get(nonce);
        byte[] ciphertext = new byte[buffer.remaining()];
        buffer.get(ciphertext);
        byte[] dataKey = kek.unwrap(wrapped, aad);
        try {
            return aesGcm(Cipher.DECRYPT_MODE, dataKey, nonce, aad, ciphertext);
        } finally {
            Arrays.fill(dataKey, (byte) 0);
        }
    }

    static byte[] aesGcm(int mode, byte[] key, byte[] nonce, byte[] aad, byte[] input) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(input);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("envelope authentication failed");
        }
    }

    /** Development KEK: AES-GCM under a local master key. */
    public static KeyEncryptionKey localKek(byte[] masterKey) {
        byte[] key = masterKey.clone();
        return new KeyEncryptionKey() {
            @Override
            public byte[] wrap(byte[] dataKey, byte[] context) {
                byte[] nonce = new byte[NONCE_LENGTH];
                RANDOM.nextBytes(nonce);
                byte[] sealed = aesGcm(Cipher.ENCRYPT_MODE, key, nonce, context, dataKey);
                return ByteBuffer.allocate(NONCE_LENGTH + sealed.length).put(nonce).put(sealed).array();
            }

            @Override
            public byte[] unwrap(byte[] wrapped, byte[] context) {
                return aesGcm(Cipher.DECRYPT_MODE, key, Arrays.copyOf(wrapped, NONCE_LENGTH), context,
                        Arrays.copyOfRange(wrapped, NONCE_LENGTH, wrapped.length));
            }
        };
    }

    /** Production KEK: Cloud KMS symmetric encrypt/decrypt with the context as additional authenticated data. */
    public static KeyEncryptionKey kmsKek(KmsClient kms, String keyName) {
        return new KeyEncryptionKey() {
            @Override
            public byte[] wrap(byte[] dataKey, byte[] context) {
                return kms.encrypt(keyName, dataKey, context);
            }

            @Override
            public byte[] unwrap(byte[] wrapped, byte[] context) {
                return kms.decrypt(keyName, wrapped, context);
            }
        };
    }
}
