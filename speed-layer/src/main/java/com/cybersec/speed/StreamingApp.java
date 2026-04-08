package com.cybersec.speed;

import com.cybersec.speed.config.KafkaConfig;
import com.cybersec.speed.detectors.BruteForceDetector;
import com.cybersec.speed.detectors.SignatureDetector;
import com.cybersec.speed.detectors.VolumeAnomalyDetector;
import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.Row;
import org.apache.spark.sql.SparkSession;
import org.apache.spark.sql.streaming.StreamingQuery;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Point d'entree principal de la couche Speed.
 *
 * Orchestre les 3 detecteurs en parallele sur le meme stream Kafka :
 *   1. BruteForceDetector     : 5+ blocked en 1 minute
 *   2. SignatureDetector      : outils connus (sqlmap, nikto...) + injections
 *   3. VolumeAnomalyDetector  : > 10 Mo en 10 secondes
 *
 * Chaque detecteur ecrit ses alertes dans Cassandra (TTL 24h).
 * La SparkSession est partagee — les 3 queries tournent dans le meme process.
 */
public class StreamingApp {

    private static final Logger logger = LoggerFactory.getLogger(StreamingApp.class);

    public static void main(String[] args) throws Exception {
        logger.info("============================================");
        logger.info("  CyberSec Speed Layer - Demarrage");
        logger.info("============================================");

        // Une seule SparkSession partagee entre les 3 detecteurs
        SparkSession spark = KafkaConfig.createStreamingSession("CyberSecStreamingApp");
        spark.sparkContext().setLogLevel("WARN");

        // Stream Kafka parse en Dataset<Row> structure
        Dataset<Row> kafkaStream = KafkaConfig.createKafkaStream(spark);

        // Lancement des 3 detecteurs en parallele
        // Chaque detecteur retourne une StreamingQuery independante
        logger.info("Lancement des 3 detecteurs...");

        StreamingQuery bruteForceQuery  = BruteForceDetector.detect(kafkaStream);
        StreamingQuery signatureQuery   = SignatureDetector.detect(kafkaStream);
        StreamingQuery volumeQuery      = VolumeAnomalyDetector.detect(kafkaStream);

        logger.info("✅ Les 3 detecteurs sont actifs.");
        logger.info("   - BruteForce Query  : {}", bruteForceQuery.name());
        logger.info("   - Signature Query   : {}", signatureQuery.name());
        logger.info("   - VolumeAnomaly Query: {}", volumeQuery.name());
        logger.info("   En attente de messages Kafka sur le topic 'cybersecurity-logs'...");

        // Attendre indéfiniment que les queries soient actives
        // En cas d'erreur sur une query, le programme s'arrete et peut etre redémarré
        spark.streams().awaitAnyTermination();

        logger.info("StreamingApp arrete.");
    }
}
