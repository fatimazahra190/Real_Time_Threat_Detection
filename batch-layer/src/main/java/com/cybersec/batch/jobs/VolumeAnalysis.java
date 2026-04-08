package com.cybersec.batch.jobs;

import com.cybersec.batch.config.SparkConfig;
import com.cybersec.batch.utils.HBaseWriter;
import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.Row;
import org.apache.spark.sql.SparkSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.spark.sql.functions.*;

/**
 * Job Spark #4 — Analyse volumetrique par type de menace.
 *
 * Correle bytes_transferred avec threat_label pour identifier les
 * patterns d'exfiltration de donnees historiques. Segmente par
 * log_type et protocol. Calcule le P95 pour detecter les outliers.
 *
 * Produit aussi la threat_timeline : evolution horaire des menaces
 * stockee dans HBase pour le dashboard historique.
 */
public class VolumeAnalysis {

    private static final Logger logger = LoggerFactory.getLogger(VolumeAnalysis.class);

    public static void main(String[] args) {
        logger.info("=== Demarrage Job: Analyse Volumetrique ===");

        SparkSession spark = SparkConfig.createSession("VolumeAnalysis");
        spark.sparkContext().setLogLevel("WARN");

        try {
            Dataset<Row> logs = spark.read().parquet(
                    SparkConfig.hdfsPath("/data/cybersecurity/logs/*/*/*")
            );

            // Analyse volumetrique
            Dataset<Row> volumeResult = analyzeVolume(logs);
            volumeResult.show(20, false);
            volumeResult.write().mode("overwrite")
                    .parquet(SparkConfig.hdfsPath("/data/cybersecurity/batch/volume_analysis"));
            logger.info("Analyse volumetrique sauvegardee.");

            // Timeline horaire
            Dataset<Row> timeline = buildTimeline(logs);
            timeline.show(24, false);
            HBaseWriter.writeThreatTimeline(timeline);
            logger.info("Timeline ecrite dans HBase.");

            logger.info("=== Job VolumeAnalysis termine ===");

        } catch (Exception e) {
            logger.error("Erreur dans VolumeAnalysis", e);
            System.exit(1);
        } finally {
            spark.stop();
        }
    }

    /**
     * Correlation bytes_transferred <-> threat_label par log_type et protocol.
     */
    public static Dataset<Row> analyzeVolume(Dataset<Row> logs) {
        return logs
                .groupBy("threat_label", "log_type", "protocol")
                .agg(
                    avg("bytes_transferred").alias("avg_bytes"),
                    max("bytes_transferred").alias("max_bytes"),
                    percentile_approx(col("bytes_transferred"), lit(0.95)).alias("p95_bytes"),
                    count("*").alias("event_count"),
                    sum("bytes_transferred").alias("total_bytes")
                )
                .orderBy(col("total_bytes").desc());
    }

    /**
     * Evolution temporelle des menaces : nombre d'evenements par heure et par categorie.
     * Stocke dans HBase pour affichage dans le dashboard historique.
     */
    public static Dataset<Row> buildTimeline(Dataset<Row> logs) {
        // Extraire date et heure depuis le timestamp
        Dataset<Row> withDateHour = logs
                .withColumn("event_date", date_format(col("timestamp"), "yyyyMMdd"))
                .withColumn("event_hour", hour(col("timestamp")));

        // Comptes par heure et par label de menace
        Dataset<Row> maliciousTimeline = withDateHour
                .filter(col("threat_label").equalTo("malicious"))
                .groupBy("event_date", "event_hour")
                .agg(count("*").alias("malicious_count"));

        Dataset<Row> suspiciousTimeline = withDateHour
                .filter(col("threat_label").equalTo("suspicious"))
                .groupBy("event_date", "event_hour")
                .agg(count("*").alias("suspicious_count"));

        Dataset<Row> benignTimeline = withDateHour
                .filter(col("threat_label").equalTo("benign"))
                .groupBy("event_date", "event_hour")
                .agg(count("*").alias("benign_count"));

        return maliciousTimeline
                .join(suspiciousTimeline, java.util.Arrays.asList("event_date", "event_hour"), "full")
                .join(benignTimeline, java.util.Arrays.asList("event_date", "event_hour"), "full")
                .na().fill(0L, new String[]{"malicious_count", "suspicious_count", "benign_count"})
                .orderBy("event_date", "event_hour");
    }
}
