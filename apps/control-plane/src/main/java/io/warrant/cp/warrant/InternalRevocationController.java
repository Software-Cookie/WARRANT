package io.warrant.cp.warrant;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;

/** Revocation feed polled by gateways. The push channel is an accelerator; this feed is the source of truth. */
@RestController
public class InternalRevocationController {

    private final WarrantStore store;

    public InternalRevocationController(WarrantStore store) {
        this.store = store;
    }

    @GetMapping("/internal/revocations")
    public List<WarrantStore.Revocation> revocations(@RequestParam("tenant") String tenant,
                                                     @RequestParam(value = "since", defaultValue = "0") long sinceEpochMs) {
        return store.revokedSince(tenant, Instant.ofEpochMilli(Math.max(0, sinceEpochMs)));
    }
}
