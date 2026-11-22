package io.warrant.chainverify;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * chain-verify — independent verification of a Warrant audit-chain export.
 *
 * <pre>
 * verify --from 1 --to 10000 --key audit-public-keys.pem --input chain.jsonl
 * </pre>
 * Exit status: 0 the range verifies, 1 verification broke (the exact index is printed), 2 usage or input error.
 */
public final class Main {

    private static final Pattern PEM = Pattern.compile(
            "-----BEGIN PUBLIC KEY-----([A-Za-z0-9+/=\\s]+)-----END PUBLIC KEY-----");

    private Main() {
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        Long from = null;
        Long to = null;
        Path key = null;
        Path input = null;
        for (int i = 0; i < args.length; i++) {
            String flag = args[i];
            if (i + 1 >= args.length) {
                return usage(err, "missing value for " + flag);
            }
            String value = args[++i];
            switch (flag) {
                case "--from" -> from = Long.parseLong(value);
                case "--to" -> to = Long.parseLong(value);
                case "--key" -> key = Path.of(value);
                case "--input" -> input = Path.of(value);
                default -> {
                    return usage(err, "unknown option " + flag);
                }
            }
        }
        if (from == null || to == null || key == null || input == null || from < 1 || to < from) {
            return usage(err, "--from, --to, --key and --input are required, with 1 <= from <= to");
        }
        try {
            List<PublicKey> keys = readKeys(key);
            List<Map<String, Object>> entries = readEntries(input, from, to);
            if (!entries.isEmpty()) {
                long last = ((java.math.BigInteger) entries.get(entries.size() - 1).get("idx")).longValue();
                to = Math.min(to, last);
            }
            ChainVerifier.Result result = new ChainVerifier(keys).verify(entries, from, to);
            if (result.ok()) {
                out.printf("OK  entries %d..%d verified (%d checked, %d signed heads, last signed idx %s, %d unsigned after it)%n",
                        from, to, result.checked(), result.signedHeads(), result.lastSignedIdx(), result.unsignedTail());
                return 0;
            }
            out.printf("BROKEN at idx %d: %s (%d entries verified before the break)%n", result.brokenAt(),
                    result.reason(), result.checked());
            return 1;
        } catch (IOException | IllegalArgumentException e) {
            err.println("chain-verify: " + e.getMessage());
            return 2;
        }
    }

    private static int usage(PrintStream err, String message) {
        err.println("chain-verify: " + message);
        err.println("usage: verify --from <idx> --to <idx> --key <public-keys.pem> --input <chain.jsonl>");
        return 2;
    }

    static List<PublicKey> readKeys(Path file) throws IOException {
        String pem = Files.readString(file, StandardCharsets.US_ASCII);
        List<PublicKey> keys = new ArrayList<>();
        Matcher matcher = PEM.matcher(pem);
        while (matcher.find()) {
            byte[] der = Base64.getMimeDecoder().decode(matcher.group(1));
            try {
                keys.add(KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der)));
            } catch (java.security.GeneralSecurityException e) {
                throw new IllegalArgumentException("not an Ed25519 public key in " + file);
            }
        }
        if (keys.isEmpty()) {
            throw new IllegalArgumentException("no public key found in " + file);
        }
        return keys;
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> readEntries(Path file, long from, long to) throws IOException {
        List<Map<String, Object>> entries = new ArrayList<>();
        try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            int lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                if (line.isBlank()) {
                    continue;
                }
                Object parsed;
                try {
                    parsed = Json.parse(line);
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException("line " + lineNumber + ": " + e.getMessage());
                }
                if (!(parsed instanceof Map<?, ?> map)) {
                    throw new IllegalArgumentException("line " + lineNumber + " is not a JSON object");
                }
                long idx = ((java.math.BigInteger) map.get("idx")).longValue();
                if (idx >= from - 1 && idx <= to) {
                    entries.add((Map<String, Object>) map);
                }
            }
        }
        return entries;
    }
}
