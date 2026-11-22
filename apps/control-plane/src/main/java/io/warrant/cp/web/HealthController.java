package io.warrant.cp.web;

import io.warrant.cp.config.WarrantProperties;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class HealthController {

    private final WarrantProperties properties;

    public HealthController(WarrantProperties properties) {
        this.properties = properties;
    }

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "up", "service", "control-plane", "version", properties.version(),
                "env", properties.env());
    }
}
