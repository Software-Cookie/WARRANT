package io.warrant.cp.keys;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.core.gcp.GcpMetadata;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Cloud KMS over REST with the workload's own identity. Asymmetric signing sends the message to KMS and receives a
 * signature: the private key is non-exportable and never present in this process.
 */
public final class KmsClient {

    private static final String BASE = "https://cloudkms.googleapis.com/v1/";
    private static final Pattern KEY_VERSION = Pattern.compile(
            "^projects/[a-z0-9-]+/locations/[a-z0-9-]+/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+/cryptoKeyVersions/[0-9]+$");
    private static final Pattern KEY = Pattern.compile(
            "^projects/[a-z0-9-]+/locations/[a-z0-9-]+/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+$");

    private final GcpMetadata metadata;
    private final HttpClient http;
    private final String baseUrl;
    private final ObjectMapper mapper = new ObjectMapper();

    public KmsClient(GcpMetadata metadata, HttpClient http, String baseUrl) {
        this.metadata = metadata;
        this.http = http;
        this.baseUrl = baseUrl == null ? BASE : baseUrl;
    }

    public static boolean isKeyVersionName(String name) {
        return name != null && KEY_VERSION.matcher(name).matches();
    }

    public static boolean isKeyName(String name) {
        return name != null && KEY.matcher(name).matches();
    }

    public byte[] asymmetricSign(String keyVersionName, byte[] data) {
        requireKeyVersion(keyVersionName);
        JsonNode response = post(keyVersionName + ":asymmetricSign", Map.of("data", b64(data)));
        return decodeField(response, "signature");
    }

    public String publicKeyPem(String keyVersionName) {
        requireKeyVersion(keyVersionName);
        JsonNode response = send(HttpRequest.newBuilder(URI.create(baseUrl + keyVersionName + "/publicKey")).GET());
        JsonNode pem = response.path("pem");
        if (!pem.isTextual()) {
            throw new KmsException("KMS returned no public key");
        }
        return pem.textValue();
    }

    public byte[] encrypt(String keyName, byte[] plaintext, byte[] aad) {
        requireKey(keyName);
        Map<String, String> body = new LinkedHashMap<>();
        body.put("plaintext", b64(plaintext));
        body.put("additionalAuthenticatedData", b64(aad));
        return decodeField(post(keyName + ":encrypt", body), "ciphertext");
    }

    public byte[] decrypt(String keyName, byte[] ciphertext, byte[] aad) {
        requireKey(keyName);
        Map<String, String> body = new LinkedHashMap<>();
        body.put("ciphertext", b64(ciphertext));
        body.put("additionalAuthenticatedData", b64(aad));
        return decodeField(post(keyName + ":decrypt", body), "plaintext");
    }

    private JsonNode post(String path, Map<String, String> body) {
        try {
            return send(HttpRequest.newBuilder(URI.create(baseUrl + path))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body))));
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new KmsException("could not encode KMS request");
        }
    }

    private JsonNode send(HttpRequest.Builder builder) {
        HttpRequest request = builder.timeout(Duration.ofSeconds(5))
                .header("Authorization", "Bearer " + metadata.accessToken())
                .build();
        try {
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new KmsException("KMS responded " + response.statusCode());
            }
            return mapper.readTree(response.body());
        } catch (IOException e) {
            throw new KmsException("KMS unreachable: " + e.getClass().getSimpleName());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new KmsException("interrupted while calling KMS");
        }
    }

    private static byte[] decodeField(JsonNode node, String field) {
        JsonNode value = node.path(field);
        if (!value.isTextual()) {
            throw new KmsException("KMS response missing " + field);
        }
        return Base64.getDecoder().decode(value.textValue());
    }

    private static String b64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private static void requireKeyVersion(String name) {
        if (!isKeyVersionName(name)) {
            throw new IllegalArgumentException("not a KMS key version resource name");
        }
    }

    private static void requireKey(String name) {
        if (!isKeyName(name)) {
            throw new IllegalArgumentException("not a KMS key resource name");
        }
    }

    public static final class KmsException extends RuntimeException {
        public KmsException(String message) {
            super(message);
        }
    }
}
