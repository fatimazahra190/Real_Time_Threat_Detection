package com.cybersec.speed.utils;

import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.CqlSessionBuilder;
import com.datastax.oss.driver.api.core.cql.PreparedStatement;
import org.apache.spark.sql.Row;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Ecrit les alertes temps reel dans Cassandra (table active_threats).
 * Concu pour etre utilise dans les foreachBatch de Spark Streaming.
 *
 * La table a un TTL de 86400s (24h) - les enregistrements sont
 * automatiquement supprimes apres 24 heures.
 */
public class CassandraWriter {

    private static final Logger logger = LoggerFactory.getLogger(CassandraWriter.class);

    private static final String CASSANDRA_HOST = System.getenv().getOrDefault("CASSANDRA_HOST", "localhost");
    private static final int    CASSANDRA_PORT  = Integer.parseInt(System.getenv().getOrDefault("CASSANDRA_PORT", "9042"));
    private static final String KEYSPACE = "cybersecurity";

    private static final String INSERT_CQL =
            "INSERT INTO " + KEYSPACE + ".active_threats " +
            "(ip_source, bucket_time, alert_id, last_seen, threat_score, " +
            " attack_types, alert_type, severity, event_count, bytes_total, " +
            " user_agents, log_sources) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    // Session partagee dans le meme executor JVM
    private static volatile CqlSession session;
    private static volatile PreparedStatement preparedInsert;

    /**
     * Obtient (ou cree) la session Cassandra de facon thread-safe.
     */
    private static CqlSession getSession() {
        if (session == null || session.isClosed()) {
            synchronized (CassandraWriter.class) {
                if (session == null || session.isClosed()) {
                    logger.info("Connexion Cassandra: {}:{}", CASSANDRA_HOST, CASSANDRA_PORT);
                    session = CqlSession.builder()
                            .addContactPoint(new InetSocketAddress(CASSANDRA_HOST, CASSANDRA_PORT))
                            .withLocalDatacenter("datacenter1")
                            .withKeyspace(KEYSPACE)
                            .build();
                    preparedInsert = session.prepare(INSERT_CQL);
                    logger.info("Connexion Cassandra etablie.");
                }
            }
        }
        return session;
    }

    /**
     * Ecrit une alerte dans Cassandra.
     * Methode statique pour etre utilisee dans les lambdas Spark.
     *
     * @param ipSource    Adresse IP source de la menace
     * @param alertType   Type d'alerte (BRUTE_FORCE, KNOWN_ATTACK_TOOL, VOLUME_ANOMALY, PORT_SCAN)
     * @param severity    Niveau de severite (LOW, MEDIUM, HIGH, CRITICAL)
     * @param threatScore Score de menace 0-100
     * @param eventCount  Nombre d'evenements dans la fenetre
     * @param bytesTotal  Total de bytes transferes
     * @param userAgent   User-Agent observe
     * @param logSource   Source de log (firewall, ids, application)
     */
    public static void writeAlert(String ipSource, String alertType, String severity,
                                   int threatScore, int eventCount, long bytesTotal,
                                   String userAgent, String logSource) {
        try {
            CqlSession cqlSession = getSession();
            Instant now = Instant.now();

            Set<String> attackTypes = new HashSet<>(Collections.singletonList(alertType));
            Set<String> userAgents  = new HashSet<>(Collections.singletonList(
                    userAgent != null ? userAgent : "unknown"));
            Set<String> logSources  = new HashSet<>(Collections.singletonList(
                    logSource != null ? logSource : "unknown"));

            cqlSession.execute(preparedInsert.bind(
                    ipSource,               // ip_source
                    now,                    // bucket_time (tronque a la minute idealement)
                    UUID.randomUUID(),      // alert_id
                    now,                    // last_seen
                    threatScore,            // threat_score
                    attackTypes,            // attack_types
                    alertType,              // alert_type
                    severity,               // severity
                    eventCount,             // event_count
                    bytesTotal,             // bytes_total
                    userAgents,             // user_agents
                    logSources              // log_sources
            ));

            logger.debug("Alerte ecrite: {} | {} | score={}", ipSource, alertType, threatScore);

        } catch (Exception e) {
            logger.error("Erreur ecriture Cassandra pour IP {}: {}", ipSource, e.getMessage(), e);
        }
    }

    /**
     * Ecriture depuis une Row Spark (usage dans foreachBatch).
     */
    public static void writeFromRow(Row row) {
        try {
            String ip         = getStringOrDefault(row, "source_ip", "unknown");
            String alertType  = getStringOrDefault(row, "alert_type", "UNKNOWN");
            String severity   = getStringOrDefault(row, "severity", "MEDIUM");
            int    score      = getIntOrDefault(row, "threat_score", 50);
            int    count      = getIntOrDefault(row, "event_count", 1);
            long   bytes      = getLongOrDefault(row, "bytes_total", 0L);
            String userAgent  = getStringOrDefault(row, "user_agent", "unknown");
            String logSource  = getStringOrDefault(row, "log_type", "unknown");

            writeAlert(ip, alertType, severity, score, count, bytes, userAgent, logSource);

        } catch (Exception e) {
            logger.error("Erreur writeFromRow: {}", e.getMessage(), e);
        }
    }

    public static void closeSession() {
        if (session != null && !session.isClosed()) {
            session.close();
            logger.info("Session Cassandra fermee.");
        }
    }

    // ── Helpers pour lire les Row Spark en evitant les NPE ──────────

    private static String getStringOrDefault(Row row, String field, String defaultVal) {
        try {
            int idx = row.fieldIndex(field);
            Object val = row.get(idx);
            return val != null ? val.toString() : defaultVal;
        } catch (Exception e) {
            return defaultVal;
        }
    }

    private static int getIntOrDefault(Row row, String field, int defaultVal) {
        try {
            int idx = row.fieldIndex(field);
            Object val = row.get(idx);
            if (val instanceof Number) return ((Number) val).intValue();
            if (val instanceof String)  return Integer.parseInt((String) val);
            return defaultVal;
        } catch (Exception e) {
            return defaultVal;
        }
    }

    private static long getLongOrDefault(Row row, String field, long defaultVal) {
        try {
            int idx = row.fieldIndex(field);
            Object val = row.get(idx);
            if (val instanceof Number) return ((Number) val).longValue();
            return defaultVal;
        } catch (Exception e) {
            return defaultVal;
        }
    }
}
