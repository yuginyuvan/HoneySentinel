package com.honeypot.discovery.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestClient;

import java.util.*;

@RestController
@CrossOrigin(origins = "*")
public class ServiceRegistryController {

    private final RestClient restClient = RestClient.builder().build();

    private final List<Map<String, Object>> registeredServices = List.of(
            Map.of("name", "api-gateway", "url", "http://localhost:8080", "type", "GATEWAY", "statusEndpoint", "http://localhost:8080/health"),
            Map.of("name", "attack-service", "url", "http://localhost:8081", "type", "CORE_HONEYPOT", "statusEndpoint", "http://localhost:8081/api/attacks/health"),
            Map.of("name", "analytics-service", "url", "http://localhost:8083", "type", "ANALYTICS", "statusEndpoint", "http://localhost:8083/api/dashboard/system-status"),
            Map.of("name", "ml-service", "url", "http://localhost:8000", "type", "AI_INTEL", "statusEndpoint", "http://localhost:8000/api/ai/health"),
            Map.of("name", "honeysentinel-ui", "url", "http://localhost:5173", "type", "FRONTEND_SOC", "statusEndpoint", "http://localhost:5173")
    );

    @GetMapping("/services")
    public ResponseEntity<List<Map<String, Object>>> getServices() {
        List<Map<String, Object>> list = new ArrayList<>();
        for (Map<String, Object> s : registeredServices) {
            Map<String, Object> item = new HashMap<>(s);
            item.put("status", checkHealth((String) s.get("statusEndpoint")));
            list.add(item);
        }
        return ResponseEntity.ok(list);
    }

    @GetMapping("/")
    public ResponseEntity<Map<String, Object>> getRegistryInfo() {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("serviceRegistry", "Honeypot AI Service Discovery Registry");
        info.put("port", 8761);
        info.put("registeredServicesCount", registeredServices.size());
        info.put("services", registeredServices);
        return ResponseEntity.ok(info);
    }

    private String checkHealth(String endpoint) {
        try {
            restClient.get().uri(endpoint).retrieve().toBodilessEntity();
            return "ONLINE";
        } catch (Exception e) {
            return "OFFLINE";
        }
    }
}
