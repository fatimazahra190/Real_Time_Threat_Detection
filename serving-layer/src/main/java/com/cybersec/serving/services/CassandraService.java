package com.cybersec.serving.services;

import com.cybersec.serving.models.ActiveAlert;
import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.cql.ResultSet;
import com.datastax.oss.driver.api.core.cql.Row;
import com.datastax.oss.driver.api.core.cql.SimpleStatement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Service Spring pour lire les alertes temps reel depuis Cassandra.
 *
 * Table lue : cybersecurity.active_threats
 * TTL : 24h (auto-nettoyage natif Cassandra)
 */
@Service
public class CassandraService {

    private static final Logger logger = LoggerFactory.getLogger(CassandraService.class);
    private static final DateTimeFormatter ISO = DateTimeFormatter.ISO_INSTANT.withZone(ZoneId.of("UTC"));

    @Autowired
    private CqlSession cqlSession;

    /**
     * Recupere les alertes actives pour une IP specifique.
     * Retourne les 10 alertes les plus recentes (CLUSTERING ORDER BY bucket_time DESC).
     *
     * @param ip Adresse IP source
     * @return Liste d'alertes actives (vide si aucune)
     */
    public List<ActiveAlert> getActiveAlerts(String ip) {
        logger.debug("Lecture Cassandra active_threats pour IP: {}", ip);

        List<ActiveAlert> alerts = new ArrayList<>();
        try {
            SimpleStatement stmt = SimpleStatement.newInstance(
                    "SELECT * FROM cybersecurity.active_threats WHERE ip_source = ? LIMIT 10",
                    ip
            );

            ResultSet rs = cqlSession.execute(stmt);
            for (Row row : rs) {
                alerts.add(mapRowToAlert(row));
            }
        } catch (Exception e) {
            logger.error("Erreur lecture Cassandra pour IP {}: {}", ip, e.getMessage());
        }

        logger.debug("IP {} -> {} alertes actives", ip, alerts.size());
        return alerts;
    }

    /**
     * Recupere toutes les alertes actives des dernieres 24h.
     * Utilisee par l'endpoint GET /threats/active.
     * Limite a 100 resultats pour eviter les surcharges.
     *
     * @return Liste de toutes les alertes actives (max 100)
     */
    public List<ActiveAlert> getAllActiveAlerts() {
        logger.debug("Lecture de toutes les alertes actives depuis Cassandra...");

        List<ActiveAlert> alerts = new ArrayList<>();
        try {
            // ALLOW FILTERING est necessaire pour un SELECT sans partition key
            // Dans un systeme de prod, on utiliserait une table secondaire par bucket_time
            SimpleStatement stmt = SimpleStatement.newInstance(
                    "SELECT * FROM cybersecurity.active_threats LIMIT 100 ALLOW FILTERING"
            );

            ResultSet rs = cqlSession.execute(stmt);
            for (Row row : rs) {
                alerts.add(mapRowToAlert(row));
            }
        } catch (Exception e) {
            logger.error("Erreur lecture toutes les alertes Cassandra: {}", e.getMessage());
        }

        // Trier par score decroissant (les plus critiques en premier)
        alerts.sort((a, b) -> Integer.compare(b.getThreatScore(), a.getThreatScore()));

        logger.debug("{} alertes actives au total", alerts.size());
        return alerts;
    }

    /**
     * Calcule le score de menace actuel d'une IP (max des alertes recentes).
     */
    public int getCurrentThreatScore(String ip) {
        List<ActiveAlert> alerts = getActiveAlerts(ip);
        return alerts.stream()
                .mapToInt(ActiveAlert::getThreatScore)
                .max()
                .orElse(0);
    }

    /**
     * Calcule le total de bytes transferes dans les alertes actives pour une IP.
     */
    public long getBytesTotal(String ip) {
        List<ActiveAlert> alerts = getActiveAlerts(ip);
        return alerts.stream()
                .mapToLong(ActiveAlert::getBytesTotal)
                .sum();
    }

    /**
     * Collecte tous les types d'attaques recentes pour une IP.
     */
    public List<String> getRecentAttackTypes(String ip) {
        List<ActiveAlert> alerts = getActiveAlerts(ip);
        Set<String> types = new LinkedHashSet<>();
        for (ActiveAlert alert : alerts) {
            if (alert.getAttackTypes() != null) types.addAll(alert.getAttackTypes());
            if (alert.getAlertType() != null)   types.add(alert.getAlertType());
        }
        return new ArrayList<>(types);
    }

    /**
     * Verifie que la connexion Cassandra est active.
     */
    public boolean isHealthy() {
        try {
            cqlSession.execute("SELECT now() FROM system.local");
            return true;
        } catch (Exception e) {
            logger.warn("Cassandra health check failed: {}", e.getMessage());
            return false;
        }
    }

    // ── Helper ───────────────────────────────────────────────────────

    private ActiveAlert mapRowToAlert(Row row) {
        ActiveAlert alert = new ActiveAlert();

        alert.setIpSource(row.getString("ip_source"));
        alert.setAlertType(row.getString("alert_type"));
        alert.setSeverity(row.getString("severity"));

        Integer score = row.getInt("threat_score");
        alert.setThreatScore(score != null ? score : 0);

        Integer eventCount = row.getInt("event_count");
        alert.setEventCount(eventCount != null ? eventCount : 0);

        Long bytes = row.getLong("bytes_total");
        alert.setBytesTotal(bytes != null ? bytes : 0L);

        // UUID -> String
        var alertId = row.getUuid("alert_id");
        alert.setAlertId(alertId != null ? alertId.toString() : null);

        // Timestamps -> ISO String
        Instant bucketTime = row.getInstant("bucket_time");
        alert.setBucketTime(bucketTime != null ? ISO.format(bucketTime) : null);

        Instant lastSeen = row.getInstant("last_seen");
        alert.setLastSeen(lastSeen != null ? ISO.format(lastSeen) : null);

        // SET<TEXT> -> Set<String>
        alert.setAttackTypes(row.getSet("attack_types", String.class));
        alert.setUserAgents(row.getSet("user_agents", String.class));
        alert.setLogSources(row.getSet("log_sources", String.class));

        return alert;
    }
}
