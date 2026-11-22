package io.warrant.chainverify;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Self-contained tests for chain-verify, runnable with nothing but a JDK (no test framework, by design).
 * usage: SelfTest <chain.jsonl> <public-key.pem>
 */
public final class SelfTest {

    private static int failures;

    private SelfTest() {
    }

    public static void main(String[] args) throws Exception {
        Path chain = Path.of(args[0]);
        Path key = Path.of(args[1]);
        List<String> lines = Files.readAllLines(chain, StandardCharsets.UTF_8);
        Path work = Files.createTempDirectory("chain-verify-selftest");

        expect("valid chain verifies", run(chain, key, 1, lines.size()), 0, "OK");
        expect("sub-range verifies when anchored by its predecessor", run(chain, key, 4000, 6000), 0, "OK");

        List<String> altered = new ArrayList<>(lines);
        altered.set(776, altered.get(776).replace("\"verdict\":\"ALLOW\"", "\"verdict\":\"DENY\""));
        expect("altering one field breaks at exactly that index", run(write(work, "altered", altered), key, 1, lines.size()),
                1, "BROKEN at idx 777");

        List<String> deleted = new ArrayList<>(lines);
        deleted.remove(4999);
        expect("deleting an entry breaks at that index", run(write(work, "deleted", deleted), key, 1, lines.size()),
                1, "BROKEN at idx 5000");

        List<String> reordered = new ArrayList<>(lines);
        String swap = reordered.get(100);
        reordered.set(100, reordered.get(101));
        reordered.set(101, swap);
        expect("reordering two entries breaks verification", run(write(work, "reordered", reordered), key, 1, lines.size()),
                1, "BROKEN at idx 101");

        Path otherKey = work.resolve("other.pem");
        java.security.KeyPair other = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        Files.writeString(otherKey, "-----BEGIN PUBLIC KEY-----\n"
                + java.util.Base64.getMimeEncoder().encodeToString(other.getPublic().getEncoded())
                + "\n-----END PUBLIC KEY-----\n");
        expect("a key that did not sign the heads is rejected", run(chain, otherKey, 1, lines.size()), 1, "head signature");

        if (failures > 0) {
            System.out.println(failures + " self-test(s) FAILED");
            System.exit(1);
        }
        System.out.println("all chain-verify self-tests passed");
    }

    private record Outcome(int status, String output) {
    }

    private static Outcome run(Path chain, Path key, long from, long to) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int status = Main.run(new String[]{"--from", String.valueOf(from), "--to", String.valueOf(to), "--key",
                key.toString(), "--input", chain.toString()}, new PrintStream(out), new PrintStream(out));
        return new Outcome(status, out.toString(StandardCharsets.UTF_8));
    }

    private static Path write(Path dir, String name, List<String> lines) throws java.io.IOException {
        Path file = dir.resolve(name + ".jsonl");
        Files.write(file, lines, StandardCharsets.UTF_8);
        return file;
    }

    private static void expect(String name, Outcome outcome, int status, String fragment) {
        boolean pass = outcome.status() == status && outcome.output().contains(fragment);
        System.out.println((pass ? "  ok    " : "  FAIL  ") + name + (pass ? "" : " -> " + outcome.status() + " " + outcome.output().strip()));
        if (!pass) {
            failures++;
        }
    }
}
