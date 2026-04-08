package com.cybersec.serving.controllers;

import com.cybersec.serving.services.CassandraService;
import com.cybersec.serving.services.HBaseService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Endpoint de sante de l'API.
 * SLA : < 50ms.
 * Utilise par Docker healthcheck et par le widget du dashboard.
 */
@RestController
@CrossOrigin(origins = "*")
public class HealthController {

    private static final Logger logger = LoggerFactory.getLogger(HealthController.class);

    @Autowired
    private HBaseService hbaseService;

    @Autowired
    private CassandraService cassandraService;

    /**
     * Verifie l'etat de l'API et de ses dependances.
     *
     * Retourne 200 si tout est UP, 503 si une dependance est DOWN.
     *
     * Reponse type :
     * {
     *   "status": "UP",
     *   "timestamp": "2023-10-15T14:00:00Z",
     *   "components": {
     *     "hbase": "UP",
     *     "cassandra": "UP",
     *     "api": "UP"
     *   }
     * }
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        logger.debug("GET /health");

        boolean hbaseOk     = false;
        boolean cassandraOk = false;

        try {
            hbaseOk = hbaseService.isHealthy();
        } catch (Exception e) {
            logger.warn("HBase health check exception: {}", e.getMessage());
        }

        try {
            cassandraOk = cassandraService.isHealthy();
        } catch (Exception e) {
            logger.warn("Cassandra health check exception: {}", e.getMessage());
        }

        Map<String, Object> response = new LinkedHashMap<>();
        Map<String, String> components = new LinkedHashMap<>();

        components.put("api",       "UP");
        components.put("hbase",     hbaseOk     ? "UP" : "DOWN");
        components.put("cassandra", cassandraOk ? "UP" : "DOWN");

        boolean allHealthy = hbaseOk && cassandraOk;
        response.put("status",     allHealthy ? "UP" : "DEGRADED");
        response.put("timestamp",  Instant.now().toString());
        response.put("components", components);

        // 200 si tout est UP, 503 si une dependance est DOWN
        return allHealthy
                ? ResponseEntity.ok(response)
                : ResponseEntity.status(503).body(response);
    }
}
