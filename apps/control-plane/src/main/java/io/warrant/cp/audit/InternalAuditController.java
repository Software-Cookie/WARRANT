package io.warrant.cp.audit;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.warrant.core.event.DecisionEvent;
import io.warrant.cp.web.ApiException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Synchronous append used by the gateway for denials, escalations and irreversible allows. */
@RestController
public class InternalAuditController {

    private final AuditChainService chain;

    public InternalAuditController(AuditChainService chain) {
        this.chain = chain;
    }

    public record AppendRequest(@JsonProperty("events") List<DecisionEvent> events) {
    }

    public record AppendResult(@JsonProperty("chain_idx") long chainIdx, @JsonProperty("duplicate") boolean duplicate) {
    }

    @PostMapping("/internal/audit/append")
    public Map<String, List<AppendResult>> append(@RequestBody AppendRequest request) {
        if (request == null || request.events() == null || request.events().isEmpty()) {
            throw ApiException.badRequest("events are required");
        }
        Map<String, List<Integer>> positionsByTenant = new LinkedHashMap<>();
        Map<String, List<DecisionEvent>> eventsByTenant = new LinkedHashMap<>();
        for (int i = 0; i < request.events().size(); i++) {
            DecisionEvent event = request.events().get(i);
            positionsByTenant.computeIfAbsent(event.tenant(), t -> new ArrayList<>()).add(i);
            eventsByTenant.computeIfAbsent(event.tenant(), t -> new ArrayList<>()).add(event);
        }
        AppendResult[] results = new AppendResult[request.events().size()];
        eventsByTenant.forEach((tenant, events) -> {
            List<AuditChainService.Appended> appended = chain.append(tenant, events);
            List<Integer> positions = positionsByTenant.get(tenant);
            for (int i = 0; i < appended.size(); i++) {
                results[positions.get(i)] = new AppendResult(appended.get(i).idx(), appended.get(i).duplicate());
            }
        });
        return Map.of("results", List.of(results));
    }
}
