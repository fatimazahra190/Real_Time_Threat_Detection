package com.cybersec.speed.config;

import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.Row;
import org.apache.spark.sql.SparkSession;
import org.apache.spark.sql.types.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.spark.sql.functions.*;

/**
 * Configuration du stream Kafka pour la couche speed.
 * Cree le stream Spark Structured Streaming depuis le topic Kafka
 * et parse les messages JSON en Dataset<Row> structure.
 */
public class KafkaConfig {

    private static final Logger logger = LoggerFactory.getLogger(KafkaConfig.class);

    private static final String KAFKA_SERVERS = System.getenv()
            .getOrDefault("KAFKA_BOOTSTRAP_SERVERS", "kafka:29092");
    private static final String TOPIC = "cybersecurity-logs";

    // Schema JSON des messages Kafka (correspond aux 10 champs du dataset)
    private static final StructType MESSAGE_SCHEMA = new StructType()
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

    /**
     * Cree le stream Kafka et retourne un Dataset<Row> structure
     * pret a etre utilise par les detecteurs.
     *
     * @param spark SparkSession configuree pour le streaming
     * @return Dataset<Row> avec les 10 champs du schema
     */
    public static Dataset<Row> createKafkaStream(SparkSession spark) {
        logger.info("Creation du stream Kafka depuis: {} | topic: {}", KAFKA_SERVERS, TOPIC);

        Dataset<Row> rawStream = spark.readStream()
                .format("kafka")
                .option("kafka.bootstrap.servers", KAFKA_SERVERS)
                .option("subscribe", TOPIC)
                .option("startingOffsets", "latest")
                .option("failOnDataLoss", "false")
                // Micro-batch toutes les 500ms pour latence < 2s
                .option("maxOffsetsPerTrigger", "10000")
                .load();

        // Parser la valeur JSON et aplatir les champs
        return rawStream
                .selectExpr("CAST(value AS STRING) as json_value",
                             "CAST(key AS STRING) as message_key")
                .select(
                    from_json(col("json_value"), MESSAGE_SCHEMA).alias("data"),
                    col("message_key")
                )
                .select("data.*");
    }

    /**
     * Cree une SparkSession configuree pour Spark Structured Streaming.
     */
    public static SparkSession createStreamingSession(String appName) {
        String hdfsHost = System.getenv().getOrDefault("HDFS_NAMENODE_HOST", "hadoop-hdfs");
        String hdfsPort = System.getenv().getOrDefault("HDFS_PORT", "9000");

        return SparkSession.builder()
                .appName(appName)
                .master("local[*]")
                .config("spark.hadoop.fs.defaultFS", "hdfs://" + hdfsHost + ":" + hdfsPort)
                .config("spark.sql.shuffle.partitions", "4")
                .config("spark.streaming.stopGracefullyOnShutdown", "true")
                // Desactiver le mode "legacy" pour les fenetres temporelles
                .config("spark.sql.legacy.timeParserPolicy", "LEGACY")
                .getOrCreate();
    }
}
