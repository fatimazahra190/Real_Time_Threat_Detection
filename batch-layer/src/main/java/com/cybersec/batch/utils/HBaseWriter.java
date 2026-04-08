package com.cybersec.batch.utils;

import com.cybersec.batch.config.SparkConfig;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HBaseConfiguration;
import org.apache.hadoop.hbase.TableName;
import org.apache.hadoop.hbase.client.*;
import org.apache.hadoop.hbase.util.Bytes;
import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.Row;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Ecrit les resultats des analyses Spark dans les tables HBase.
 * Chaque methode correspond a une table HBase specifique.
 */
public class HBaseWriter {

    private static final Logger logger = LoggerFactory.getLogger(HBaseWriter.class);

    private static final byte[] STATS_CF = Bytes.toBytes("stats");
    private static final byte[] META_CF  = Bytes.toBytes("meta");
    private static final byte[] PATTERN_CF = Bytes.toBytes("pattern");
    private static final byte[] FREQ_CF    = Bytes.toBytes("freq");
    private static final byte[] COUNTS_CF    = Bytes.toBytes("counts");
    private static final byte[] BREAKDOWN_CF = Bytes.toBytes("breakdown");

    /**
     * Cree la configuration HBase a partir des variables d'environnement.
     */
    private static Configuration createHBaseConfig() {
        Configuration config = HBaseConfiguration.create();
        config.set("hbase.zookeeper.quorum", SparkConfig.getZookeeperHost());
        config.set("hbase.zookeeper.property.clientPort", "2181");
        config.set("hbase.master", SparkConfig.getHbaseHost() + ":16000");
        return config;
    }

    /**
     * Ecrit les resultats du Top 10 IPs dans la table ip_reputation.
     *
     * @param results Dataset contenant: source_ip, log_type, total_events,
     *                unique_targets, total_bytes, reputation_score
     */
    public static void writeIPReputation(Dataset<Row> results) {
        logger.info("Ecriture des reputations IP dans HBase...");
        List<Row> rows = results.collectAsList();

        try (Connection conn = ConnectionFactory.createConnection(createHBaseConfig());
             Table table = conn.getTable(TableName.valueOf("ip_reputation"))) {

            List<Put> puts = new ArrayList<>();
            String now = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);

            for (Row row : rows) {
                String ip = row.getString(row.fieldIndex("source_ip"));
                byte[] rowKey = Bytes.toBytes(ip);
                Put put = new Put(rowKey);

                // Famille stats
                put.addColumn(STATS_CF, Bytes.toBytes("score"),
                        Bytes.toBytes(String.valueOf(row.getLong(row.fieldIndex("reputation_score")))));
                put.addColumn(STATS_CF, Bytes.toBytes("total_events"),
                        Bytes.toBytes(String.valueOf(row.getLong(row.fieldIndex("total_events")))));
                put.addColumn(STATS_CF, Bytes.toBytes("unique_targets"),
                        Bytes.toBytes(String.valueOf(row.getLong(row.fieldIndex("unique_targets")))));
                put.addColumn(STATS_CF, Bytes.toBytes("total_bytes"),
                        Bytes.toBytes(String.valueOf(row.getLong(row.fieldIndex("total_bytes")))));

                // Famille meta
                put.addColumn(META_CF, Bytes.toBytes("last_seen"), Bytes.toBytes(now));
                put.addColumn(META_CF, Bytes.toBytes("log_types"),
                        Bytes.toBytes(row.getString(row.fieldIndex("log_type"))));

                puts.add(put);
                logger.debug("IP {} -> score {}", ip, row.getLong(row.fieldIndex("reputation_score")));
            }

            table.put(puts);
            logger.info("✅ {} enregistrements IP ecrits dans HBase (ip_reputation)", puts.size());

        } catch (IOException e) {
            logger.error("Erreur ecriture HBase ip_reputation: {}", e.getMessage(), e);
            throw new RuntimeException("Echec ecriture HBase", e);
        }
    }

    /**
     * Ecrit les patterns d'attaque dans la table attack_patterns.
     *
     * @param results     Dataset avec source_ip et colonnes d'attaque
     * @param attackType  Type d'attaque (PORT_SCAN, SQLI, XSS, TOOL_DETECTED...)
     */
    public static void writeAttackPattern(Dataset<Row> results, String attackType) {
        logger.info("Ecriture des patterns {} dans HBase...", attackType);
        List<Row> rows = results.collectAsList();

        try (Connection conn = ConnectionFactory.createConnection(createHBaseConfig());
             Table table = conn.getTable(TableName.valueOf("attack_patterns"))) {

            List<Put> puts = new ArrayList<>();
            String now = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);

            for (Row row : rows) {
                String ip = row.getString(row.fieldIndex("source_ip"));
                // Row key composite: TYPE|IP
                String rowKeyStr = attackType + "|" + ip;
                Put put = new Put(Bytes.toBytes(rowKeyStr));

                put.addColumn(PATTERN_CF, Bytes.toBytes("category"), Bytes.toBytes(attackType));
                put.addColumn(PATTERN_CF, Bytes.toBytes("source_ip"), Bytes.toBytes(ip));

                // Ajouter count si disponible
                if (hasField(row, "distinct_targets")) {
                    put.addColumn(FREQ_CF, Bytes.toBytes("count"),
                            Bytes.toBytes(String.valueOf(row.getLong(row.fieldIndex("distinct_targets")))));
                }
                if (hasField(row, "event_count")) {
                    put.addColumn(FREQ_CF, Bytes.toBytes("event_count"),
                            Bytes.toBytes(String.valueOf(row.getLong(row.fieldIndex("event_count")))));
                }

                put.addColumn(FREQ_CF, Bytes.toBytes("last_seen"), Bytes.toBytes(now));
                puts.add(put);
            }

            table.put(puts);
            logger.info("✅ {} patterns {} ecrits dans HBase", puts.size(), attackType);

        } catch (IOException e) {
            logger.error("Erreur ecriture HBase attack_patterns: {}", e.getMessage(), e);
            throw new RuntimeException("Echec ecriture HBase", e);
        }
    }

    /**
     * Ecrit les donnees de timeline dans HBase.
     *
     * @param results Dataset avec date, hour, malicious_count, suspicious_count
     */
    public static void writeThreatTimeline(Dataset<Row> results) {
        logger.info("Ecriture de la timeline dans HBase...");
        List<Row> rows = results.collectAsList();

        try (Connection conn = ConnectionFactory.createConnection(createHBaseConfig());
             Table table = conn.getTable(TableName.valueOf("threat_timeline"))) {

            List<Put> puts = new ArrayList<>();

            for (Row row : rows) {
                String date = row.getString(row.fieldIndex("event_date"));
                String hour = String.valueOf(row.getInt(row.fieldIndex("event_hour")));
                String rowKeyStr = date + "|" + hour;
                Put put = new Put(Bytes.toBytes(rowKeyStr));

                if (hasField(row, "malicious_count")) {
                    put.addColumn(COUNTS_CF, Bytes.toBytes("malicious"),
                            Bytes.toBytes(String.valueOf(row.getLong(row.fieldIndex("malicious_count")))));
                }
                if (hasField(row, "suspicious_count")) {
                    put.addColumn(COUNTS_CF, Bytes.toBytes("suspicious"),
                            Bytes.toBytes(String.valueOf(row.getLong(row.fieldIndex("suspicious_count")))));
                }
                if (hasField(row, "benign_count")) {
                    put.addColumn(COUNTS_CF, Bytes.toBytes("benign"),
                            Bytes.toBytes(String.valueOf(row.getLong(row.fieldIndex("benign_count")))));
                }

                puts.add(put);
            }

            table.put(puts);
            logger.info("✅ {} entrees timeline ecrites dans HBase", puts.size());

        } catch (IOException e) {
            logger.error("Erreur ecriture HBase threat_timeline: {}", e.getMessage(), e);
            throw new RuntimeException("Echec ecriture HBase", e);
        }
    }

    private static boolean hasField(Row row, String fieldName) {
        try {
            row.fieldIndex(fieldName);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
