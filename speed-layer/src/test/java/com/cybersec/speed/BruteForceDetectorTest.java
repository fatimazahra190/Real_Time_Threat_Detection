package com.cybersec.speed;

import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.Row;
import org.apache.spark.sql.RowFactory;
import org.apache.spark.sql.SparkSession;
import org.apache.spark.sql.types.*;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

import static org.apache.spark.sql.functions.*;
import static org.junit.Assert.*;

/**
 * Tests unitaires pour la logique de detection du BruteForceDetector.
 * Simule des micro-batches sans connexion Kafka ni Cassandra.
 */
public class BruteForceDetectorTest {

    private static SparkSession spark;

    private static final StructType SCHEMA = new StructType()
            .add("timestamp",         DataTypes.TimestampType, true)
            .add("source_ip",         DataTypes.StringType,    true)
            .add("dest_ip",           DataTypes.StringType,    true)
            .add("protocol",          DataTypes.StringType,    true)
            .add("action",            DataTypes.StringType,    true)
            .add("threat_label",      DataTypes.StringType,    true)
            .add("log_type",          DataTypes.StringType,    true)
            .add("bytes_transferred", DataTypes.LongType,      true)
            .add("user_agent",        DataTypes.StringType,    true)
            .add("request_path",      DataTypes.StringType,    true);

    @BeforeClass
    public static void setUp() {
        spark = SparkSession.builder()
                .appName("BruteForceDetectorTest")
                .master("local[1]")
                .config("spark.sql.shuffle.partitions", "1")
                .getOrCreate();
        spark.sparkContext().setLogLevel("ERROR");
    }

    @AfterClass
    public static void tearDown() {
        if (spark != null) spark.stop();
    }

    /**
     * Simule la logique de filtrage du detecteur brute-force sur un micro-batch.
     */
    private Dataset<Row> simulateBruteForceLogic(Dataset<Row> batch, int threshold) {
        return batch
                .filter(col("action").equalTo("blocked"))
                .groupBy(col("source_ip"))
                .agg(
                    count("*").alias("blocked_count"),
                    first("user_agent").alias("user_agent"),
                    first("log_type").alias("log_type"),
                    sum("bytes_transferred").alias("bytes_total")
                )
                .filter(col("blocked_count").gt(threshold))
                .withColumn("threat_score",
                    least(lit(100),
                        lit(70).plus(col("blocked_count").minus(lit(threshold)).multiply(2))
                    ).cast("integer")
                )
                .withColumn("severity",
                    when(col("blocked_count").gt(10), "CRITICAL").otherwise("HIGH")
                )
                .withColumn("alert_type", lit("BRUTE_FORCE"));
    }

    @Test
    public void testBruteForceDetectedWith6Attempts() {
        // 6 connexions bloquees depuis la meme IP dans la fenetre
        Timestamp ts = Timestamp.valueOf("2023-10-15 14:00:00");
        List<Row> data = new ArrayList<>();
        String attackerIP = "192.168.100.5";

        for (int i = 0; i < 6; i++) {
            data.add(RowFactory.create(
                    ts, attackerIP, "192.168.0.10", "HTTP", "blocked",
                    "malicious", "firewall", 512L, "hydra/9.4", "/admin/login"
            ));
        }

        Dataset<Row> batch = spark.createDataFrame(data, SCHEMA);
        Dataset<Row> alerts = simulateBruteForceLogic(batch, 5);

        assertEquals("Une alerte doit etre generee", 1L, alerts.count());

        Row alert = alerts.first();
        assertEquals("IP correcte", attackerIP, alert.getString(alert.fieldIndex("source_ip")));
        assertEquals("Type d'alerte correct", "BRUTE_FORCE", alert.getString(alert.fieldIndex("alert_type")));
        assertEquals("Severite HIGH pour 6 tentatives", "HIGH", alert.getString(alert.fieldIndex("severity")));

        int score = alert.getInt(alert.fieldIndex("threat_score"));
        assertTrue("Score >= 70", score >= 70);
        assertTrue("Score <= 100", score <= 100);
    }

    @Test
    public void testNoAlertWith4Attempts() {
        // Seulement 4 connexions bloquees - sous le seuil de 5
        Timestamp ts = Timestamp.valueOf("2023-10-15 14:00:00");
        List<Row> data = new ArrayList<>();

        for (int i = 0; i < 4; i++) {
            data.add(RowFactory.create(
                    ts, "10.0.0.1", "10.0.0.100", "SSH", "blocked",
                    "suspicious", "ids", 256L, "ssh-scanner/1.0", "/ssh"
            ));
        }

        Dataset<Row> batch = spark.createDataFrame(data, SCHEMA);
        Dataset<Row> alerts = simulateBruteForceLogic(batch, 5);

        assertEquals("Aucune alerte sous le seuil", 0L, alerts.count());
    }

    @Test
    public void testCriticalSeverityWith11Attempts() {
        // 11 tentatives -> CRITICAL
        Timestamp ts = Timestamp.valueOf("2023-10-15 14:00:00");
        List<Row> data = new ArrayList<>();

        for (int i = 0; i < 11; i++) {
            data.add(RowFactory.create(
                    ts, "172.16.0.99", "192.168.1.1", "HTTP", "blocked",
                    "malicious", "firewall", 1024L, "hydra/9.5", "/login"
            ));
        }

        Dataset<Row> batch = spark.createDataFrame(data, SCHEMA);
        Dataset<Row> alerts = simulateBruteForceLogic(batch, 5);

        assertEquals("Une alerte generee", 1L, alerts.count());
        Row alert = alerts.first();
        assertEquals("Severite CRITICAL pour > 10 tentatives", "CRITICAL",
                alert.getString(alert.fieldIndex("severity")));
    }

    @Test
    public void testOnlyBlockedActionsTriggered() {
        // Melange de allowed et blocked - seuls les blocked comptent
        Timestamp ts = Timestamp.valueOf("2023-10-15 14:00:00");
        List<Row> data = new ArrayList<>();
        String ip = "10.5.5.5";

        // 3 blocked (sous le seuil de 5)
        for (int i = 0; i < 3; i++) {
            data.add(RowFactory.create(ts, ip, "10.0.0.1", "HTTP", "blocked",
                    "suspicious", "firewall", 100L, "curl", "/"));
        }
        // 5 allowed (ne doivent pas compter)
        for (int i = 0; i < 5; i++) {
            data.add(RowFactory.create(ts, ip, "10.0.0.1", "HTTP", "allowed",
                    "benign", "application", 200L, "Mozilla/5.0", "/index.html"));
        }

        Dataset<Row> batch = spark.createDataFrame(data, SCHEMA);
        Dataset<Row> alerts = simulateBruteForceLogic(batch, 5);

        assertEquals("Aucune alerte : seulement 3 blocked (< 5)", 0L, alerts.count());
    }
}
