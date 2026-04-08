package com.cybersec.serving.controllers;

import com.cybersec.serving.models.ActiveAlert;
import com.cybersec.serving.models.ThreatProfile;
import com.cybersec.serving.services.CassandraService;
import com.cybersec.serving.services.HBaseService;
import com.cybersec.serving.services.ThreatFusionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

/**
 * Controller REST principal pour l'exposition des donnees de menaces.
 *
 * Endpoints disponibles (PRD Section 5.1.1) :
 *   GET /threats/ip/{ip}    - Profil complet d'une IP (batch + speed)    < 200ms
 *   GET /threats/active     - Liste menaces actives (< 24h)               < 300ms
 *   GET /threats/stats      - Statistiques globales (batch)               < 500ms
 *   GET /threats/timeline   - Evolution temporelle des menaces            < 500ms
 */
@RestController
@RequestMapping("/threats")
@CrossOrigin(origins = "*")  // Permet les appels depuis le dashboard HTML
public class ThreatController {

    private static final Logger logger = LoggerFactory.getLogger(ThreatController.class);

    @Autowired
    private ThreatFusionService threatFusionService;

    @Autowired
    private CassandraService cassandraService;

    @Autowired
    private HBaseService hbaseService;

    /**
     * Profil complet d'une IP : fusion batch (HBase) + speed (Cassandra).
     * SLA : < 200ms (p95).
     *
     * Exemple de reponse :
     * {
     *   "ip": "192.168.1.45",
     *   "batch_layer": { "reputation_score": 87, ... },
     *   "speed_layer":  { "active_alerts": 3, ... },
     *   "recommendation": "BLOCK",
     *   "confidence": 0.94
     * }
     */
    @GetMapping("/ip/{ip}")
    public ResponseEntity<ThreatProfile> getThreatProfile(@PathVariable String ip) {
        logger.info("GET /threats/ip/{}", ip);

        // Validation basique de l'IP
        if (ip == null || ip.isBlank() || ip.length() > 45) {
            return ResponseEntity.badRequest().build();
        }

        ThreatProfile profile = threatFusionService.getThreatProfile(ip.trim());
        return ResponseEntity.ok(profile);
    }

    /**
     * Liste de toutes les alertes actives (Cassandra, TTL 24h).
     * SLA : < 300ms. Limite a 100 resultats.
     */
    @GetMapping("/active")
    public ResponseEntity<List<ActiveAlert>> getAllActiveAlerts() {
        logger.info("GET /threats/active");
        List<ActiveAlert> alerts = cassandraService.getAllActiveAlerts();
        return ResponseEntity.ok(alerts);
    }

    /**
     * Statistiques globales depuis la couche batch (HBase).
     * SLA : < 500ms.
     */
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getGlobalStats() {
        logger.info("GET /threats/stats");
        Map<String, Object> stats = hbaseService.getGlobalStats();
        return ResponseEntity.ok(stats);
    }

    /**
     * Evolution temporelle des menaces.
     * SLA : < 500ms.
     *
     * Parametres :
     *   from : date de debut au format yyyyMMdd (defaut: hier)
     *   to   : date de fin au format yyyyMMdd (defaut: aujourd'hui)
     */
    @GetMapping("/timeline")
    public ResponseEntity<List<Map<String, Object>>> getTimeline(
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to) {

        logger.info("GET /threats/timeline from={} to={}", from, to);

        String today     = LocalDate.now().format(DateTimeFormatter.ofPattern("yyyyMMdd"));
        String yesterday = LocalDate.now().minusDays(1).format(DateTimeFormatter.ofPattern("yyyyMMdd"));

        String fromDate = (from != null && !from.isBlank()) ? from : yesterday;
        String toDate   = (to   != null && !to.isBlank())   ? to   : today;

        List<Map<String, Object>> timeline = hbaseService.getTimeline(fromDate, toDate);
        return ResponseEntity.ok(timeline);
    }
}
