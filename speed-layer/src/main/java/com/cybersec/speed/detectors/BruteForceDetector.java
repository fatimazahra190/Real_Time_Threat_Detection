package com.cybersec.speed.detectors;

import com.cybersec.speed.utils.CassandraWriter;
import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.Row;
import org.apache.spark.sql.streaming.StreamingQuery;
import org.apache.spark.sql.streaming.StreamingQueryException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.spark.sql.functions.*;

/**
 * Detecteur de brute-force en temps reel.
 *
 * Declencheur : 5+ connexions bloquees (action=blocked) depuis le meme
 * source_ip dans une fenetre glissante de 1 minute.
 *
 * Score : 70 + 2 par tentative supplementaire, plafonne a 100.
 * Severite : HIGH si 5-10 tentatives, CRITICAL si > 10.
 * Latence cible : < 2 secondes depuis le dernier log.
 *
 * Reference : OWASP OTG-AUTHN-003.
 */
public class BruteForceDetector {

    private static final Logger logger = LoggerFactory.getLogger(BruteForceDetector.class);

    private static final int THRESHOLD     = 5;   // Nombre min de tentatives
    private static final String TIME_WINDOW = "1 minute";
    private static final String CHECKPOINT  = "/tmp/checkpoint/bruteforce";

    /**
     * Lance le stream de detection brute-force.
     *
     * @param stream Dataset<Row> depuis Kafka (structure avec les 10 champs)
     * @return StreamingQuery active (a maintenir en vie avec awaitTermination)
     */
    public static StreamingQuery detect(Dataset<Row> stream) {
        logger.info("Demarrage detecteur BruteForce | seuil={} | fenetre={}", THRESHOLD, TIME_WINDOW);

        Dataset<Row> alerts = stream
                // Filtrer uniquement les connexions bloquees
                .filter(col("action").equalTo("blocked"))
                // Fenetres glissantes de 1 minute par IP source
                .groupBy(
                    window(col("timestamp"), TIME_WINDOW),
                    col("source_ip")
                )
                .agg(
                    count("*").alias("blocked_count"),
                    first("user_agent").alias("user_agent"),
                    first("log_type").alias("log_type"),
                    sum("bytes_transferred").alias("bytes_total")
                )
                // Seuil de detection : au moins 5 tentatives bloquees
                .filter(col("blocked_count").gt(THRESHOLD))
                // Calcul du score : 70 base + 2 par tentative supplementaire (max 100)
                .withColumn("threat_score",
                    least(lit(100),
                        lit(70).plus(col("blocked_count").minus(lit(THRESHOLD)).multiply(2))
                    ).cast("integer")
                )
                // Severite selon l'intensite de l'attaque
                .withColumn("severity",
                    when(col("blocked_count").gt(10), "CRITICAL")
                    .otherwise("HIGH")
                )
                .withColumn("alert_type", lit("BRUTE_FORCE"))
                .withColumn("event_count", col("blocked_count").cast("integer"));

        return alerts.writeStream()
                .outputMode("update")
                .option("checkpointLocation", CHECKPOINT)
                .foreachBatch((batchDF, batchId) -> {
                    long alertCount = batchDF.count();
                    if (alertCount > 0) {
                        logger.warn("Batch {} - {} alertes BRUTE_FORCE detectees", batchId, alertCount);
                        batchDF.show(false);
                        // Ecrire dans Cassandra
                        batchDF.foreach(row -> CassandraWriter.writeFromRow(row));
                    }
                })
                .start();
    }
}
