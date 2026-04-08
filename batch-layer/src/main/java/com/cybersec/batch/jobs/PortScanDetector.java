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
 * Job Spark #2 — Detection de scans de ports (batch).
 *
 * Detecte les comportements de port scanning en analysant les logs TCP :
 * une IP qui contacte plus de 20 adresses dest_ip distinctes en moins
 * de 5 minutes est consideree comme effectuant un scan de ports.
 *
 * Resultats ecrits dans HDFS (/data/cybersecurity/batch/port_scans)
 * et dans HBase (table attack_patterns).
 */
public class PortScanDetector {

    private static final Logger logger = LoggerFactory.getLogger(PortScanDetector.class);

    // Seuil de detection : nombre minimal de cibles distinctes
    private static final int PORT_SCAN_THRESHOLD = 20;
    // Fenetre temporelle en minutes
    private static final String TIME_WINDOW = "5 minutes";

    public static void main(String[] args) {
        logger.info("=== Demarrage Job: Detection Port Scanning ===");

        SparkSession spark = SparkConfig.createSession("PortScanDetector");
        spark.sparkContext().setLogLevel("WARN");

        try {
            Dataset<Row> result = detect(spark);

            result.show(20, false);

            String outputPath = SparkConfig.hdfsPath("/data/cybersecurity/batch/port_scans");
            result.write().mode("overwrite").parquet(outputPath);
            logger.info("Resultats sauvegardes: {}", outputPath);

            HBaseWriter.writeAttackPattern(result, "PORT_SCAN");

            logger.info("=== Job PortScanDetector termine: {} scans detectes ===", result.count());

        } catch (Exception e) {
            logger.error("Erreur dans PortScanDetector", e);
            System.exit(1);
        } finally {
            spark.stop();
        }
    }

    /**
     * Logique principale de detection (testable separement).
     */
    public static Dataset<Row> detect(SparkSession spark) {
        String inputPath = SparkConfig.hdfsPath("/data/cybersecurity/logs/*/*/*");
        Dataset<Row> logs = spark.read().parquet(inputPath);

        return logs
                // Filtrer uniquement le protocole TCP
                .filter(col("protocol").equalTo("TCP"))
                // Grouper par IP source et fenetre temporelle de 5 minutes
                .groupBy(col("source_ip"), window(col("timestamp"), TIME_WINDOW))
                // Compter les destinations distinctes dans la fenetre
                .agg(
                    countDistinct("dest_ip").alias("distinct_targets"),
                    count("*").alias("event_count"),
                    first("log_type").alias("log_type")
                )
                // Filtrer les scans probables : > 20 cibles differentes
                .filter(col("distinct_targets").gt(PORT_SCAN_THRESHOLD))
                // Ajouter le label d'attaque et le score
                .withColumn("attack_type", lit("PORT_SCAN"))
                .withColumn("threat_score",
                    // Score : 60 + min(40, distinct_targets - 20)
                    least(lit(100),
                        lit(60).plus(col("distinct_targets").minus(lit(PORT_SCAN_THRESHOLD)))
                    ).cast("int")
                )
                .withColumn("severity",
                    when(col("distinct_targets").gt(100), "CRITICAL")
                    .when(col("distinct_targets").gt(50), "HIGH")
                    .otherwise("MEDIUM")
                )
                // Extraire les bornes de la fenetre pour lisibilite
                .withColumn("window_start", col("window.start"))
                .withColumn("window_end", col("window.end"))
                .drop("window")
                .orderBy(col("distinct_targets").desc());
    }
}
