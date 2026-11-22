package io.warrant.cp.approval;

import io.warrant.cp.web.ApiException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

/** Gateway-facing escalation lifecycle: park, poll, claim for release, report the released call's result. */
@RestController
public class InternalEscalationController {

    private final EscalationService escalations;
    private final DeliveryDispatcher delivery;

    public InternalEscalationController(EscalationService escalations, DeliveryDispatcher delivery) {
        this.escalations = escalations;
        this.delivery = delivery;
    }

    @PostMapping("/internal/escalations")
    public EscalationModels.Parked park(@RequestBody EscalationModels.ParkRequest request) {
        if (request == null || request.tenant() == null || request.audit() == null || request.warrantChain() == null) {
            throw ApiException.badRequest("tenant, warrant_chain and audit are required");
        }
        EscalationModels.Parked parked = escalations.park(request);
        if (parked.coalescedInto() == null) {
            delivery.deliverAsync(request.tenant(), parked.escalationId());
        }
        return parked;
    }

    @GetMapping("/internal/escalations/{id}")
    public ResponseEntity<EscalationModels.Status> status(@PathVariable("id") String id, @RequestParam("tenant") String tenant,
                                                          @RequestParam("wids") String wids) {
        List<String> callerWids = Arrays.stream(wids.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
        return escalations.statusForAgent(tenant, id, callerWids).map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping("/internal/escalations/releasable")
    public List<String> releasable(@RequestParam("tenant") String tenant,
                                   @RequestParam(value = "limit", defaultValue = "20") int limit) {
        return escalations.releasable(tenant, limit);
    }

    @PostMapping("/internal/escalations/{id}/claim")
    public ResponseEntity<EscalationModels.ReleaseTicket> claim(@PathVariable("id") String id,
                                                                @RequestParam("tenant") String tenant,
                                                                @RequestBody Map<String, String> body) {
        String claimant = body == null ? null : body.get("claimant");
        if (claimant == null || claimant.isBlank()) {
            throw ApiException.badRequest("claimant is required");
        }
        return escalations.claim(tenant, id, claimant).map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.status(409).build());
    }

    @PostMapping("/internal/escalations/{id}/result")
    public ResponseEntity<Void> result(@PathVariable("id") String id, @RequestParam("tenant") String tenant,
                                       @RequestBody EscalationModels.ReleaseResult result) {
        escalations.recordResult(tenant, id, result);
        return ResponseEntity.noContent().build();
    }
}
