package com.cybersec.speed.detectors;

import com.cybersec.speed.utils.CassandraWriter;
import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.Row;
import org.apache.spark.sql.streaming.StreamingQuery;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.spark.sql.functions.*;

/**
 * Detecteur d'anomalies volumetriques en temps reel.
 *
 * Declencheur : sum(bytes_transferred) > 10 Mo (10 485 760 bytes)
 * par IP source dans une fenetre de 10 secondes.
 *
 * Cas d'usage : exfiltration de donnees, DDoS sortant, transfert non autorise.
 * Score : 80 + log10(bytes/1Mo)*5, plafonne a 100.
 * Severite : HIGH (10-100 Mo), CRITICAL (> 100 Mo en 10 sec).
 */
public class VolumeAnomalyDetector {

    private static final Logger logger = LoggerFactory.getLogger(VolumeAnomalyDetector.class);

    private static final long   THRESHOLD_BYTES = 10L * 1024 * 1024; // 10 Mo
    private static final long   CRITICAL_BYTES  = 100L * 1024 * 1024; // 100 Mo
    private static final String TIME_WINDOW     = "10 seconds";
    private static final String CHECKPOINT      = "/tmp/checkpoint/volume";

    /**
     * Lance le stream de detection d'anomalies volumetriques.
     *
     * @param stream Dataset<Row> depuis Kafka
     * @return StreamingQuery active
     */
    public static StreamingQuery detect(Dataset<Row> stream) {
        logger.info("Demarrage detecteur VolumeAnomaly | seuil={}Mo | fenetre={}",
                THRESHOLD_BYTES / (1024 * 1024), TIME_WINDOW);

        Dataset<Row> alerts = stream
                .groupBy(
                    window(col("timestamp"), TIME_WINDOW),
                    col("source_ip")
                )
                .agg(
                    sum("bytes_transferred").alias("bytes_total"),
                    count("*").alias("event_count"),
                    first("log_type").alias("log_type"),
                    first("user_agent").alias("user_agent"),
                    first("dest_ip").alias("dest_ip")
                )
                // Seuil : plus de 10 Mo en 10 secondes
                .filter(col("bytes_total").gt(THRESHOLD_BYTES))
                .withColumn("alert_type", lit("VOLUME_ANOMALY"))
                // Score : 80 + log10(bytes/1Mo)*5, max 100
                .withColumn("threat_score",
                    least(lit(100),
                        lit(80).plus(
                            log(lit(10.0),
                                col("bytes_total").divide(lit(1048576.0))
                            ).multiply(5)
                        ).cast("integer")
                    )
                )
                .withColumn("severity",
                    when(col("bytes_total").gt(CRITICAL_BYTES), "CRITICAL")
                    .otherwise("HIGH")
                );

        return alerts.writeStream()
                .outputMode("update")
                .option("checkpointLocation", CHECKPOINT)
                .foreachBatch((batchDF, batchId) -> {
                    long alertCount = batchDF.count();
                    if (alertCount > 0) {
                        logger.warn("Batch {} - {} anomalies volumetriques detectees", batchId, alertCount);
                        batchDF.show(false);
                        batchDF.foreach(row -> CassandraWriter.writeFromRow(row));
                    }
                })
                .start();
    }
}
