package io.warrant.pep.broker;

import io.warrant.core.registry.ToolDefinition;
import io.warrant.core.secrets.SecretResolver;
import io.warrant.core.secrets.SecretValue;
import org.springframework.stereotype.Component;

/**
 * Fetches a target-system credential by reference at the moment a decided call is forwarded. The agent never holds
 * it: the only path to the target that carries the credential is this gateway. The value lives for one request and
 * is never logged, persisted or returned.
 */
@Component
public class CredentialBroker {

    private final SecretResolver secrets;

    public CredentialBroker(SecretResolver secrets) {
        this.secrets = secrets;
    }

    public SecretValue credentialFor(ToolDefinition tool) {
        if (tool.credentialRef() == null || tool.credentialRef().isBlank()) {
            throw new SecretResolver.SecretUnavailableException(tool.id(), "tool has no credential reference");
        }
        return secrets.resolve(tool.credentialRef());
    }
}
