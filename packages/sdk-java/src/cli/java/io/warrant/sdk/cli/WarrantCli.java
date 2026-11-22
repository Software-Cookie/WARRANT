package io.warrant.sdk.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.warrant.policy.cli.PolicyCli;
import io.warrant.sdk.AgentKey;

import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

/**
 * {@code warrant} command line. Talks to the control plane as a signed-in person: {@code WARRANT_TOKEN} holds an
 * OIDC ID token in production; locally {@code --dev-email} (or {@code WARRANT_DEV_EMAIL}) obtains a development
 * session. Tokens are read from the environment, never from arguments, so they do not land in shell history.
 */
public final class WarrantCli {

    private static final String USAGE = """
            usage: warrant <command> [options]
              audit verify   [--from N] [--to N]                      verify the hash chain and signed heads
              audit trace    [--target T] [--verb V] [--principal P] [--limit N]
              audit export   --format jsonl|csv|evidence-pack [--from N] [--to N] --out FILE
              policy lint|test|compile FILE...                        offline, no server needed
              warrant issue  --agent NAME --build-hash H --mandate TEXT --scope a,b --rows N
                             --cnf KEY [--ttl SECONDS] [--hops N] [--irreversible]
              warrant revoke WID [--reason TEXT]
              escalations list
              escalations show ID
              escalations decide ID --action approve|deny|approve_partial
              keygen --out DIR                                        agent proof-of-possession key pair
            global: --cp URL (WARRANT_CONTROL_PLANE_URL)  --tenant ID (WARRANT_TENANT)  --dev-email E (WARRANT_DEV_EMAIL)
            """;

    private final PrintStream out;
    private final PrintStream err;
    private final ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final Map<String, String> options = new LinkedHashMap<>();
    private final List<String> positional = new ArrayList<>();
    private String bearer;

    WarrantCli(PrintStream out, PrintStream err) {
        this.out = out;
        this.err = err;
    }

    public static void main(String[] args) {
        System.exit(new WarrantCli(System.out, System.err).run(args));
    }

    int run(String[] args) {
        if (args.length == 0 || "--help".equals(args[0]) || "help".equals(args[0])) {
            out.print(USAGE);
            return args.length == 0 ? 2 : 0;
        }
        if ("policy".equals(args[0])) {
            return PolicyCli.run(Arrays.copyOfRange(args, 1, args.length), out, err);
        }
        parse(Arrays.copyOfRange(args, 1, args.length));
        try {
            return switch (args[0]) {
                case "audit" -> audit();
                case "warrant" -> warrant();
                case "escalations" -> escalations();
                case "keygen" -> keygen();
                default -> usage("unknown command " + args[0]);
            };
        } catch (CliFailure e) {
            err.println("warrant: " + e.getMessage());
            return 1;
        }
    }

    private int audit() {
        String sub = sub();
        switch (sub) {
            case "verify" -> {
                JsonNode report = get("/v1/audit/verify?" + query("from", "to"));
                print(report);
                if (!report.path("ok").asBoolean(false)) {
                    err.println("CHAIN BROKEN at index " + report.path("broken_at").asText("?") + ": "
                            + report.path("reason").asText(""));
                    return 1;
                }
                out.println("chain verified: " + report.path("checked").asLong() + " entries, "
                        + report.path("signed_heads_verified").asLong() + " signed heads");
                return 0;
            }
            case "trace" -> {
                print(get("/v1/audit/trace?" + query("target", "verb", "principal", "since", "until", "limit")));
                return 0;
            }
            case "export" -> {
                String file = required("out");
                ObjectNode body = mapper.createObjectNode().put("format", options.getOrDefault("format", "jsonl"));
                if (options.containsKey("from")) {
                    body.put("from", Long.parseLong(options.get("from")));
                }
                if (options.containsKey("to")) {
                    body.put("to", Long.parseLong(options.get("to")));
                }
                byte[] bytes = send("POST", "/v1/audit/export", body).body();
                write(Path.of(file), bytes);
                out.println("wrote " + bytes.length + " bytes to " + file);
                return 0;
            }
            default -> {
                return usage("unknown audit command " + sub);
            }
        }
    }

    private int warrant() {
        String sub = sub();
        switch (sub) {
            case "issue" -> {
                ObjectNode body = mapper.createObjectNode()
                        .put("agent", required("agent"))
                        .put("build_hash", required("build-hash"))
                        .put("mandate", required("mandate"))
                        .put("ttl_seconds", Long.parseLong(options.getOrDefault("ttl", "900")))
                        .put("hops", Integer.parseInt(options.getOrDefault("hops", "3")))
                        .put("cnf", required("cnf"));
                body.putArray("scope").addAll(Arrays.stream(required("scope").split(",")).map(String::trim)
                        .map(mapper.getNodeFactory()::textNode).toList());
                body.putObject("ceiling").put("rows", Long.parseLong(required("rows")))
                        .put("irreversible", options.containsKey("irreversible")).put("spend", 0);
                JsonNode issued = json(send("POST", "/v1/warrants", body).body());
                print(issued);
                return 0;
            }
            case "revoke" -> {
                String wid = positionalAt(0, "WID");
                String reason = options.containsKey("reason") ? "?reason=" + encode(options.get("reason")) : "";
                print(json(send("DELETE", "/v1/warrants/" + encode(wid) + reason, null).body()));
                return 0;
            }
            default -> {
                return usage("unknown warrant command " + sub);
            }
        }
    }

    private int escalations() {
        String sub = sub();
        switch (sub) {
            case "list" -> {
                print(get("/v1/escalations?state=" + encode(options.getOrDefault("state", "pending"))));
                return 0;
            }
            case "show" -> {
                print(get("/v1/escalations/" + encode(positionalAt(0, "ID"))));
                return 0;
            }
            case "decide" -> {
                String id = positionalAt(0, "ID");
                JsonNode detail = get("/v1/escalations/" + encode(id));
                ObjectNode body = mapper.createObjectNode().put("action", required("action"))
                        .put("version", detail.path("version").asInt());
                print(json(send("POST", "/v1/escalations/" + encode(id) + "/decision", body).body()));
                return 0;
            }
            default -> {
                return usage("unknown escalations command " + sub);
            }
        }
    }

    private int keygen() {
        Path dir = Path.of(required("out"));
        try {
            Files.createDirectories(dir);
        } catch (IOException e) {
            throw new CliFailure("cannot create " + dir);
        }
        AgentKey key = AgentKey.generate();
        key.writePemFiles(dir.resolve("agent.key.pem"), dir.resolve("agent.pub.pem"));
        out.println(key.confirmation());
        return 0;
    }

    // ------------------------------------------------------------------ transport

    private JsonNode get(String path) {
        return json(send("GET", path, null).body());
    }

    private HttpResponse<byte[]> send(String method, String path, JsonNode body) {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(controlPlane() + path))
                .timeout(Duration.ofSeconds(60))
                .header("Authorization", "Bearer " + bearer())
                .header("Accept", "application/json");
        String tenant = option("tenant", "WARRANT_TENANT");
        if (tenant != null) {
            request.header("X-Warrant-Tenant", tenant);
        }
        if (body != null) {
            request.header("Content-Type", "application/json").method(method, HttpRequest.BodyPublishers.ofString(body.toString()));
        } else {
            request.method(method, HttpRequest.BodyPublishers.noBody());
        }
        HttpResponse<byte[]> response = exchange(request.build());
        if (response.statusCode() >= 400) {
            JsonNode error = json(response.body());
            throw new CliFailure("HTTP " + response.statusCode() + " " + error.path("error").asText("")
                    + (error.hasNonNull("message") ? ": " + error.path("message").asText() : ""));
        }
        return response;
    }

    private String bearer() {
        if (bearer != null) {
            return bearer;
        }
        String token = System.getenv("WARRANT_TOKEN");
        if (token != null && !token.isBlank()) {
            bearer = token.trim();
            return bearer;
        }
        String email = option("dev-email", "WARRANT_DEV_EMAIL");
        if (email == null) {
            throw new CliFailure("set WARRANT_TOKEN (OIDC ID token) or, locally, --dev-email / WARRANT_DEV_EMAIL");
        }
        HttpResponse<byte[]> response = exchange(HttpRequest.newBuilder(URI.create(controlPlane() + "/v1/dev/session"))
                .timeout(Duration.ofSeconds(10)).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(mapper.createObjectNode().put("email", email).toString())).build());
        if (response.statusCode() != 200) {
            throw new CliFailure("development sign-in refused (HTTP " + response.statusCode() + ")");
        }
        bearer = json(response.body()).path("token").asText();
        return bearer;
    }

    private HttpResponse<byte[]> exchange(HttpRequest request) {
        try {
            return http.send(request, HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException e) {
            throw new CliFailure("control plane unreachable at " + controlPlane());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new CliFailure("interrupted");
        }
    }

    private String controlPlane() {
        String url = option("cp", "WARRANT_CONTROL_PLANE_URL");
        return (url == null ? "http://localhost:8081" : url).replaceAll("/+$", "");
    }

    // ------------------------------------------------------------------ arguments

    private void parse(String[] args) {
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (arg.startsWith("--")) {
                String name = arg.substring(2);
                boolean flag = i + 1 >= args.length || args[i + 1].startsWith("--");
                options.put(name, flag ? "true" : args[++i]);
            } else {
                positional.add(arg);
            }
        }
    }

    private String sub() {
        if (positional.isEmpty()) {
            throw new CliFailure("missing sub-command; see warrant --help");
        }
        return positional.remove(0);
    }

    private String positionalAt(int index, String name) {
        if (positional.size() <= index) {
            throw new CliFailure("missing " + name);
        }
        return positional.get(index);
    }

    private String required(String name) {
        String value = options.get(name);
        if (value == null || value.isBlank() || "true".equals(value) && !"irreversible".equals(name)) {
            throw new CliFailure("--" + name + " is required");
        }
        return value;
    }

    private String option(String name, String env) {
        String value = options.get(name);
        if (value != null) {
            return value;
        }
        String fromEnv = System.getenv(env);
        return fromEnv == null || fromEnv.isBlank() ? null : fromEnv;
    }

    private String query(String... names) {
        StringJoiner joiner = new StringJoiner("&");
        for (String name : names) {
            if (options.containsKey(name)) {
                joiner.add(name + "=" + encode(options.get(name)));
            }
        }
        return joiner.toString();
    }

    private JsonNode json(byte[] body) {
        try {
            return body.length == 0 ? mapper.createObjectNode() : mapper.readTree(body);
        } catch (IOException e) {
            return mapper.createObjectNode().put("text", new String(body, StandardCharsets.UTF_8));
        }
    }

    private void print(JsonNode node) {
        try {
            out.println(mapper.writeValueAsString(node));
        } catch (IOException e) {
            throw new CliFailure("cannot render response");
        }
    }

    private static void write(Path file, byte[] bytes) {
        try {
            Files.write(file, bytes);
        } catch (IOException e) {
            throw new CliFailure("cannot write " + file);
        }
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private int usage(String message) {
        err.println("warrant: " + message);
        err.print(USAGE);
        return 2;
    }

    private static final class CliFailure extends RuntimeException {
        private static final long serialVersionUID = 1L;

        CliFailure(String message) {
            super(message);
        }
    }
}
