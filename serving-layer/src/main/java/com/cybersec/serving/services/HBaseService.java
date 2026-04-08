package com.cybersec.serving.services;

import com.cybersec.serving.models.IPReputation;
import org.apache.hadoop.hbase.TableName;
import org.apache.hadoop.hbase.client.*;
import org.apache.hadoop.hbase.util.Bytes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.*;

/**
 * Service Spring pour lire les donnees batch depuis HBase.
 *
 * Tables lues :
 *   - ip_reputation    : score historique par IP
 *   - attack_patterns  : patterns d'attaques detectes par batch
 *   - threat_timeline  : evolution horaire des menaces
 */
@Service
public class HBaseService {

    private static final Logger logger = LoggerFactory.getLogger(HBaseService.class);

    private static final byte[] STATS_CF    = Bytes.toBytes("stats");
    private static final byte[] META_CF     = Bytes.toBytes("meta");
    private static final byte[] FREQ_CF     = Bytes.toBytes("freq");
    private static final byte[] COUNTS_CF   = Bytes.toBytes("counts");

    @Autowired
    private Connection hbaseConnection;

    /**
     * Recupere le profil de reputation historique d'une IP depuis HBase.
     * Si l'IP n'existe pas dans HBase, retourne un profil vide (score=0).
     *
     * @param ip Adresse IP a interroger
     * @return IPReputation avec les donnees batch, ou profil vide si inconnue
     */
    public IPReputation getIPReputation(String ip) {
        logger.debug("Lecture HBase ip_reputation pour IP: {}", ip);

        IPReputation reputation = new IPReputation(ip);

        try (Table table = hbaseConnection.getTable(TableName.valueOf("ip_reputation"))) {
            Get get = new Get(Bytes.toBytes(ip));
            Result result = table.get(get);

            if (result.isEmpty()) {
                logger.debug("IP {} non trouvee dans HBase - profil vide retourne", ip);
                return reputation;
            }

            // Famille stats
            String scoreStr = getColumn(result, STATS_CF, "score");
            if (scoreStr != null) reputation.setReputationScore(Long.parseLong(scoreStr));

            String eventsStr = getColumn(result, STATS_CF, "total_events");
            if (eventsStr != null) reputation.setTotalHistoricalEvents(Long.parseLong(eventsStr));

            String targetsStr = getColumn(result, STATS_CF, "unique_targets");
            if (targetsStr != null) reputation.setUniqueTargets(Long.parseLong(targetsStr));

            String bytesStr = getColumn(result, STATS_CF, "total_bytes");
            if (bytesStr != null) reputation.setTotalBytes(Long.parseLong(bytesStr));

            // Famille meta
            String lastSeen = getColumn(result, META_CF, "last_seen");
            reputation.setLastBatchUpdate(lastSeen);

            String logTypes = getColumn(result, META_CF, "log_types");
            reputation.setLogTypes(logTypes);

            logger.debug("IP {} -> score={}, events={}",
                    ip, reputation.getReputationScore(), reputation.getTotalHistoricalEvents());

        } catch (IOException e) {
            logger.error("Erreur lecture HBase pour IP {}: {}", ip, e.getMessage());
            // Retourner le profil vide plutot que de planter l'API
        }

        return reputation;
    }

    /**
     * Recupere les patterns d'attaque pour une IP depuis la table attack_patterns.
     *
     * @param ip Adresse IP
     * @return Liste des types d'attaques detectes en batch
     */
    public List<String> getAttackTypes(String ip) {
        List<String> attackTypes = new ArrayList<>();
        String[] knownTypes = {"PORT_SCAN", "SQLI", "XSS", "LFI", "TOOL_DETECTED", "BRUTE_FORCE"};

        try (Table table = hbaseConnection.getTable(TableName.valueOf("attack_patterns"))) {
            for (String type : knownTypes) {
                String rowKey = type + "|" + ip;
                Get get = new Get(Bytes.toBytes(rowKey));
                Result result = table.get(get);
                if (!result.isEmpty()) {
                    attackTypes.add(type);
                }
            }
        } catch (IOException e) {
            logger.error("Erreur lecture attack_patterns pour IP {}: {}", ip, e.getMessage());
        }

        return attackTypes;
    }

    /**
     * Recupere les donnees de timeline (evolution horaire des menaces).
     * Utilisee par l'endpoint /threats/timeline.
     *
     * @param fromDate Date de debut au format yyyyMMdd
     * @param toDate   Date de fin au format yyyyMMdd
     * @return Map<heure, compteurs> pour chaque heure dans la plage
     */
    public List<Map<String, Object>> getTimeline(String fromDate, String toDate) {
        List<Map<String, Object>> timeline = new ArrayList<>();

        try (Table table = hbaseConnection.getTable(TableName.valueOf("threat_timeline"))) {
            // Scan de la plage de dates
            Scan scan = new Scan();
            scan.withStartRow(Bytes.toBytes(fromDate + "|00"));
            scan.withStopRow(Bytes.toBytes(toDate + "|24"));
            scan.addFamily(COUNTS_CF);

            try (ResultScanner scanner = table.getScanner(scan)) {
                for (Result result : scanner) {
                    String rowKey = Bytes.toString(result.getRow());
                    String[] parts = rowKey.split("\\|");
                    if (parts.length < 2) continue;

                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("date", parts[0]);
                    entry.put("hour", parts[1]);

                    String malicious  = getColumn(result, COUNTS_CF, "malicious");
                    String suspicious = getColumn(result, COUNTS_CF, "suspicious");
                    String benign     = getColumn(result, COUNTS_CF, "benign");

                    entry.put("malicious",  malicious  != null ? Long.parseLong(malicious)  : 0L);
                    entry.put("suspicious", suspicious != null ? Long.parseLong(suspicious) : 0L);
                    entry.put("benign",     benign     != null ? Long.parseLong(benign)     : 0L);

                    timeline.add(entry);
                }
            }
        } catch (IOException e) {
            logger.error("Erreur lecture timeline HBase: {}", e.getMessage());
        }

        return timeline;
    }

    /**
     * Recupere les statistiques globales depuis HBase pour /threats/stats.
     */
    public Map<String, Object> getGlobalStats() {
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("source", "batch_layer");
        stats.put("note", "Resultats des derniers jobs Spark batch");

        // Compter les IPs avec un score > 70 (menaces critiques)
        // Dans une implementation complete, on ferait un scan filtre sur ip_reputation
        // Ici on retourne un apercu simplifie
        try (Table table = hbaseConnection.getTable(TableName.valueOf("ip_reputation"))) {
            Scan scan = new Scan();
            scan.addFamily(STATS_CF);
            int highRiskCount = 0;
            int totalIPs = 0;

            try (ResultScanner scanner = table.getScanner(scan)) {
                for (Result result : scanner) {
                    totalIPs++;
                    String scoreStr = getColumn(result, STATS_CF, "score");
                    if (scoreStr != null && Long.parseLong(scoreStr) > 70) {
                        highRiskCount++;
                    }
                }
            }

            stats.put("total_ips_analyzed", totalIPs);
            stats.put("high_risk_ips", highRiskCount);

        } catch (IOException e) {
            logger.error("Erreur lecture stats HBase: {}", e.getMessage());
            stats.put("error", "HBase temporarily unavailable");
        }

        return stats;
    }

    /**
     * Verifie que la connexion HBase est active.
     * Utilisee par le health check.
     */
    public boolean isHealthy() {
        try (Table table = hbaseConnection.getTable(TableName.valueOf("ip_reputation"))) {
            table.exists(new Get(Bytes.toBytes("health_check")));
            return true;
        } catch (IOException e) {
            logger.warn("HBase health check failed: {}", e.getMessage());
            return false;
        }
    }

    // ── Helper ───────────────────────────────────────────────────────

    private String getColumn(Result result, byte[] family, String qualifier) {
        byte[] value = result.getValue(family, Bytes.toBytes(qualifier));
        return value != null ? Bytes.toString(value) : null;
    }
}
