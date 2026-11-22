package io.warrant.cp.audit;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.core.crypto.Ed25519;
import io.warrant.core.verify.VerificationKey;
import io.warrant.cp.identity.AuthFilter;
import io.warrant.cp.identity.Identity;
import io.warrant.cp.identity.Role;
import io.warrant.cp.web.ApiException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

@RestController
@RequestMapping("/v1/audit")
public class AuditController {

    private static final Role[] READERS = {Role.AUDITOR, Role.SECURITY_ADMIN, Role.OWNER, Role.APPROVER};

    private final AuditQueries queries;
    private final ChainVerificationService verification;
    private final ObjectMapper mapper;

    public AuditController(AuditQueries queries, ChainVerificationService verification, ObjectMapper mapper) {
        this.queries = queries;
        this.verification = verification;
        this.mapper = mapper;
    }

    /** The post-incident question as one query: who authorized what, under which policy, approved by whom. */
    @GetMapping("/trace")
    public Map<String, Object> trace(@RequestParam(value = "target", required = false) String target,
                                     @RequestParam(value = "verb", required = false) String verb,
                                     @RequestParam(value = "principal", required = false) String principal,
                                     @RequestParam(value = "since", required = false) Instant since,
                                     @RequestParam(value = "until", required = false) Instant until,
                                     @RequestParam(value = "limit", defaultValue = "50") int limit,
                                     HttpServletRequest request) {
        Identity identity = AuthFilter.current(request).requireAny(READERS);
        List<Map<String, Object>> entries = queries.trace(identity.tenant(),
                new AuditQueries.TraceFilter(target, verb, principal, since, until, limit));
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("entries", entries);
        response.put("chain", verification.verify(identity.tenant(), 1, Long.MAX_VALUE));
        return response;
    }

    @GetMapping("/verify")
    public ChainVerificationService.Report verify(@RequestParam(value = "from", defaultValue = "1") long from,
                                                  @RequestParam(value = "to", defaultValue = "9223372036854775807") long to,
                                                  HttpServletRequest request) {
        Identity identity = AuthFilter.current(request).requireAny(READERS);
        return verification.verify(identity.tenant(), from, to);
    }

    @GetMapping(value = "/public-keys", produces = "application/x-pem-file")
    public String publicKeys(HttpServletRequest request) {
        Identity identity = AuthFilter.current(request).requireAny(READERS);
        StringBuilder pem = new StringBuilder();
        for (VerificationKey key : verification.auditKeys(identity.tenant())) {
            pem.append("# kid: ").append(key.kid()).append('\n').append(Ed25519.toPem(key.key()));
        }
        return pem.toString();
    }

    public record ExportRequest(@JsonProperty("from") Long from, @JsonProperty("to") Long to,
                                @JsonProperty("format") String format) {
    }

    @PostMapping("/export")
    public ResponseEntity<StreamingResponseBody> export(@RequestBody ExportRequest body, HttpServletRequest request) {
        Identity identity = AuthFilter.current(request).requireAny(Role.AUDITOR, Role.SECURITY_ADMIN, Role.OWNER);
        String tenant = identity.tenant();
        long from = body.from() == null ? 1 : Math.max(1, body.from());
        long to = body.to() == null ? verification.headIndex(tenant) : Math.min(body.to(), verification.headIndex(tenant));
        String format = body.format() == null ? "jsonl" : body.format();
        return switch (format) {
            case "jsonl" -> download("warrant-audit-" + tenant + ".jsonl", "application/x-ndjson",
                    out -> writeJsonl(tenant, from, to, out));
            case "csv" -> download("warrant-audit-" + tenant + ".csv", "text/csv", out -> writeCsv(tenant, from, to, out));
            case "evidence-pack" -> download("warrant-evidence-" + tenant + "-" + from + "-" + to + ".zip",
                    "application/zip", out -> writeEvidencePack(tenant, from, to, identity.email(), out));
            default -> throw ApiException.badRequest("format must be evidence-pack, jsonl or csv");
        };
    }

    private static ResponseEntity<StreamingResponseBody> download(String filename, String contentType,
                                                                  StreamingResponseBody body) {
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                .contentType(MediaType.parseMediaType(contentType))
                .body(body);
    }

    private void writeJsonl(String tenant, long from, long to, OutputStream out) throws IOException {
        IOException[] failure = new IOException[1];
        queries.export(tenant, from, to, row -> {
            try {
                out.write(mapper.writeValueAsBytes(row));
                out.write('\n');
            } catch (IOException e) {
                failure[0] = e;
            }
        });
        if (failure[0] != null) {
            throw failure[0];
        }
    }

    private void writeCsv(String tenant, long from, long to, OutputStream out) throws IOException {
        String[] columns = {"idx", "decided_at", "principal", "agent_id", "tool_id", "verb", "target", "verdict",
                "reason_code", "stage", "policy_v", "model_v", "approver", "latency_ms", "arg_digest", "entry_digest"};
        out.write((String.join(",", columns) + "\n").getBytes(StandardCharsets.UTF_8));
        queries.export(tenant, from, to, row -> {
            StringBuilder line = new StringBuilder();
            for (int i = 0; i < columns.length; i++) {
                if (i > 0) {
                    line.append(',');
                }
                line.append(csv(row.get(columns[i])));
            }
            line.append('\n');
            try {
                out.write(line.toString().getBytes(StandardCharsets.UTF_8));
            } catch (IOException e) {
                throw new java.io.UncheckedIOException(e);
            }
        });
    }

    /** Values beginning with formula characters are prefixed so a spreadsheet never evaluates them. */
    static String csv(Object value) {
        if (value == null) {
            return "";
        }
        String text = value.toString();
        if (!text.isEmpty() && "=+-@\t\r".indexOf(text.charAt(0)) >= 0) {
            text = "'" + text;
        }
        return "\"" + text.replace("\"", "\"\"") + "\"";
    }

    private void writeEvidencePack(String tenant, long from, long to, String exportedBy, OutputStream out)
            throws IOException {
        ByteArrayOutputStream chain = new ByteArrayOutputStream();
        writeJsonl(tenant, from, to, chain);
        ChainVerificationService.Report report = verification.verify(tenant, from, to);
        StringBuilder keys = new StringBuilder();
        for (VerificationKey key : verification.auditKeys(tenant)) {
            keys.append("# kid: ").append(key.kid()).append('\n').append(Ed25519.toPem(key.key()));
        }
        Map<String, Object> manifest = new LinkedHashMap<>();
        manifest.put("format", "warrant-evidence-pack/1");
        manifest.put("tenant", tenant);
        manifest.put("from", from);
        manifest.put("to", to);
        manifest.put("exported_at", Instant.now().toString());
        manifest.put("exported_by", exportedBy);
        manifest.put("record_rule", "entry_digest(n) = sha256(utf8(prev_digest(n-1)) || canonical_json(record(n)))");
        manifest.put("verify_with", "chain-verify --from " + from + " --to " + to + " --key audit-public-keys.pem --input chain.jsonl");
        try (ZipOutputStream zip = new ZipOutputStream(out)) {
            entry(zip, "manifest.json", mapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(manifest));
            entry(zip, "chain.jsonl", chain.toByteArray());
            entry(zip, "audit-public-keys.pem", keys.toString().getBytes(StandardCharsets.US_ASCII));
            entry(zip, "verification.json", mapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(report));
            entry(zip, "README.txt", ("""
                    Warrant evidence pack. The chain contains digests and identifiers only, never tool-call arguments.
                    Verify independently of Warrant with the open-source chain-verify tool:

                        %s

                    A record that was altered, deleted or reordered breaks verification at its exact index.
                    """.formatted(manifest.get("verify_with"))).getBytes(StandardCharsets.UTF_8));
        }
    }

    private static void entry(ZipOutputStream zip, String name, byte[] content) throws IOException {
        zip.putNextEntry(new ZipEntry(name));
        zip.write(content);
        zip.closeEntry();
    }
}
