package io.warrant.cp.approval;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.warrant.core.secrets.SecretResolver;
import io.warrant.core.secrets.SecretValue;
import io.warrant.cp.config.WarrantProperties;
import io.warrant.cp.db.TenantScope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Delivers approval cards to every configured channel independently: one failing channel never blocks the others,
 * and an escalation with every channel down stays pending in the console — it is never auto-approved.
 * Chat and email messages carry the plain-English card and a console link, never the raw call or its arguments.
 */
@Component
public class DeliveryDispatcher {

    private static final Logger LOG = LoggerFactory.getLogger(DeliveryDispatcher.class);

    private final TenantScope scope;
    private final SecretResolver secrets;
    private final HttpClient http;
    private final ObjectMapper mapper;
    private final WarrantProperties.Channels channels;

    public DeliveryDispatcher(TenantScope scope, SecretResolver secrets, HttpClient outboundHttpClient,
                              ObjectMapper mapper, WarrantProperties properties) {
        this.scope = scope;
        this.secrets = secrets;
        this.http = outboundHttpClient;
        this.mapper = mapper;
        this.channels = properties.channels();
    }

    public void deliverAsync(String tenant, String escalationId) {
        Thread.ofVirtual().name("deliver-" + escalationId).start(() -> deliver(tenant, escalationId));
    }

    void deliver(String tenant, String escalationId) {
        JsonNode card;
        try {
            String stored = scope.run(tenant, jdbc -> jdbc.queryForObject(
                    "SELECT card::text FROM escalations WHERE id = ?", String.class, escalationId));
            card = mapper.readTree(stored);
        } catch (RuntimeException | java.io.IOException e) {
            LOG.warn("could not load card {} for delivery: {}", escalationId, e.getClass().getSimpleName());
            return;
        }
        String link = channels.consoleBaseUrl() + "/approve/" + escalationId;
        String text = summary(card, link);
        Map<String, Object> outcomes = new LinkedHashMap<>();
        outcomes.put("console", outcome("delivered"));
        outcomes.put("google_chat", attempt(() -> webhook(channels.chatWebhookSecret(), Map.of("text", text))));
        outcomes.put("slack", attempt(() -> webhook(channels.slackWebhookSecret(), Map.of("text", text))));
        outcomes.put("email", attempt(() -> email(tenant, card.path("headline").asText("Approval required"), text)));
        try {
            String json = mapper.writeValueAsString(outcomes);
            scope.runVoid(tenant, jdbc -> jdbc.update("UPDATE escalations SET delivery = ?::jsonb WHERE id = ?", json,
                    escalationId));
        } catch (RuntimeException | com.fasterxml.jackson.core.JsonProcessingException e) {
            LOG.warn("could not record delivery outcome for {}", escalationId);
        }
    }

    static String summary(JsonNode card, String link) {
        JsonNode provenance = card.path("provenance");
        return card.path("headline").asText("An agent action needs approval") + "\n"
                + "Requested by " + provenance.path("requested_by").asText("an agent")
                + " on behalf of " + provenance.path("on_behalf_of").asText("unknown") + "\n"
                + "Mandate: \"" + provenance.path("mandate").asText("") + "\"\n"
                + card.path("risk").asText("") + "\n"
                + "If nobody responds by " + card.path("expires_at").asText("the deadline") + ", it is denied.\n"
                + "Review: " + link;
    }

    private interface Attempt {
        String run() throws Exception;
    }

    private static Map<String, Object> attempt(Attempt attempt) {
        try {
            return outcome(attempt.run());
        } catch (Exception e) {
            return outcome("failed: " + e.getClass().getSimpleName());
        }
    }

    private static Map<String, Object> outcome(String status) {
        return Map.of("status", status, "at", Instant.now().toString());
    }

    private String webhook(String secretRef, Map<String, Object> payload) throws Exception {
        if (secretRef == null || secretRef.isBlank()) {
            return "not_configured";
        }
        try (SecretValue url = secrets.resolve(secretRef)) {
            URI target = URI.create(url.reveal());
            if (!"https".equals(target.getScheme())) {
                return "rejected: webhook must use https";
            }
            HttpResponse<Void> response = http.send(HttpRequest.newBuilder(target)
                    .timeout(Duration.ofSeconds(5))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(mapper.writeValueAsBytes(payload)))
                    .build(), HttpResponse.BodyHandlers.discarding());
            return response.statusCode() < 300 ? "delivered" : "failed: HTTP " + response.statusCode();
        }
    }

    private String email(String tenant, String subject, String text) throws Exception {
        if (channels.smtpSecret() == null || channels.smtpSecret().isBlank() || channels.emailFrom().isBlank()) {
            return "not_configured";
        }
        List<String> recipients = scope.run(tenant, jdbc -> jdbc.queryForList(
                "SELECT email FROM approvers WHERE 'email' = ANY (channels)", String.class));
        if (recipients.isEmpty()) {
            return "no_recipients";
        }
        try (SecretValue smtp = secrets.resolve(channels.smtpSecret())) {
            JsonNode config = mapper.readTree(smtp.reveal());
            JavaMailSenderImpl sender = new JavaMailSenderImpl();
            sender.setHost(config.path("host").asText());
            sender.setPort(config.path("port").asInt(587));
            sender.setUsername(config.path("username").asText());
            sender.setPassword(config.path("password").asText());
            sender.getJavaMailProperties().put("mail.smtp.starttls.required", "true");
            sender.getJavaMailProperties().put("mail.smtp.auth", "true");
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(channels.emailFrom());
            message.setTo(recipients.toArray(String[]::new));
            message.setSubject("[Warrant] " + subject);
            message.setText(text);
            sender.send(message);
            return "delivered";
        }
    }
}
