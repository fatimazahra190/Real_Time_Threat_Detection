package com.cybersec.batch.jobs;

import com.cybersec.batch.config.SparkConfig;
import com.cybersec.batch.utils.HBaseWriter;
import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.Row;
import org.apache.spark.sql.SparkSession;
import org.apache.spark.sql.functions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.spark.sql.functions.*;

/**
 * Job Spark #1 — Top 10 des IPs sources malveillantes.
 *
 * Analyse les logs historiques pour identifier les IPs les plus actives
 * parmi les evenements suspicious et malicious. Calcule un score de
 * reputation de 0 a 100 et ecrit les resultats dans HBase (ip_reputation)
 * et HDFS (/data/cybersecurity/batch/ip_reputation).
 */
public class TopMaliciousIPs {

    private static final Logger logger = LoggerFactory.getLogger(TopMaliciousIPs.class);

    public static void main(String[] args) {
        logger.info("=== Demarrage Job: Top 10 IPs Malveillantes ===");

        SparkSession spark = SparkConfig.createSession("TopMaliciousIPs");
        spark.sparkContext().setLogLevel("WARN");

        try {
            Dataset<Row> result = analyze(spark);

            // Affichage console pour validation
            logger.info("--- Resultats Top 10 IPs ---");
            result.show(10, false);

            // Sauvegarde HDFS
            String outputPath = SparkConfig.hdfsPath("/data/cybersecurity/batch/ip_reputation");
            result.write().mode("overwrite").parquet(outputPath);
            logger.info("Resultats sauvegardes dans HDFS: {}", outputPath);

            // Ecriture HBase
            HBaseWriter.writeIPReputation(result);

            logger.info("=== Job TopMaliciousIPs termine avec succes ===");

        } catch (Exception e) {
            logger.error("Erreur dans le job TopMaliciousIPs", e);
            System.exit(1);
        } finally {
            spark.stop();
        }
    }

    /**
     * Logique d'analyse principale — peut etre testee independamment.
     */
    public static Dataset<Row> analyze(SparkSession spark) {
        // Lecture depuis HDFS (partitionne par date)
        String inputPath = SparkConfig.hdfsPath("/data/cybersecurity/logs/*/*/*");
        logger.info("Lecture des logs depuis: {}", inputPath);

        Dataset<Row> logs = spark.read().parquet(inputPath);
        logger.info("Schema du dataset:");
        logs.printSchema();
        logger.info("Nombre total de logs: {}", logs.count());

        // Compter par categorie pour le scoring
        Dataset<Row> byCategoryAndIP = logs
                .groupBy("source_ip", "log_type", "threat_label")
                .agg(
                    count("*").alias("count_by_label"),
                    sum("bytes_transferred").alias("bytes_by_label")
                );

        // Filtrer suspicious + malicious et calculer les metriques globales
        Dataset<Row> suspicious = logs
                .filter(col("threat_label").isin("suspicious", "malicious"))
                .groupBy("source_ip", "log_type")
                .agg(
                    count("*").alias("total_events"),
                    countDistinct("dest_ip").alias("unique_targets"),
                    sum("bytes_transferred").alias("total_bytes")
                );

        // Calcul des comptes par type de menace pour le scoring
        Dataset<Row> maliciousCount = logs
                .filter(col("threat_label").equalTo("malicious"))
                .groupBy("source_ip")
                .agg(count("*").alias("malicious_count"));

        Dataset<Row> suspiciousCount = logs
                .filter(col("threat_label").equalTo("suspicious"))
                .groupBy("source_ip")
                .agg(count("*").alias("suspicious_count"));

        // Jointures pour obtenir les donnees completes
        Dataset<Row> joined = suspicious
                .join(maliciousCount, "source_ip")
                .join(suspiciousCount, "source_ip")
                .withColumn("reputation_score",
                    // score = (malicious*10 + suspicious*5) / total * 100, plafonne a 100
                    least(
                        lit(100L),
                        col("malicious_count").multiply(10)
                            .plus(col("suspicious_count").multiply(5))
                            .divide(col("total_events"))
                            .multiply(100)
                            .cast("long")
                    )
                )
                .orderBy(col("total_events").desc())
                .limit(10);

        return joined;
    }
}
