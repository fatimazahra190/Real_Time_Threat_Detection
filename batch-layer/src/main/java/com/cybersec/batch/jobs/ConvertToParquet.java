package com.cybersec.batch.jobs;

import com.cybersec.batch.config.SparkConfig;
import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.Row;
import org.apache.spark.sql.SparkSession;
import org.apache.spark.sql.types.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.spark.sql.functions.*;

/**
 * Convertit le dataset CSV en format Parquet partitionne par date dans HDFS.
 * A executer en premier, avant tous les autres jobs batch.
 *
 * Usage:
 *   spark-submit --class com.cybersec.batch.jobs.ConvertToParquet batch-layer.jar \
 *     --input /local/cybersecurity_threat_detection_logs.csv \
 *     --output hdfs://hadoop-hdfs:9000/data/cybersecurity/logs/
 */
public class ConvertToParquet {

    private static final Logger logger = LoggerFactory.getLogger(ConvertToParquet.class);

    // Schema explicite pour eviter les erreurs de type a la lecture
    private static final StructType SCHEMA = new StructType()
            .add("timestamp",        DataTypes.TimestampType, false)
            .add("source_ip",        DataTypes.StringType,    false)
            .add("dest_ip",          DataTypes.StringType,    false)
            .add("protocol",         DataTypes.StringType,    false)
            .add("action",           DataTypes.StringType,    false)
            .add("threat_label",     DataTypes.StringType,    false)
            .add("log_type",         DataTypes.StringType,    false)
            .add("bytes_transferred",DataTypes.LongType,      true)
            .add("user_agent",       DataTypes.StringType,    true)
            .add("request_path",     DataTypes.StringType,    true);

    public static void main(String[] args) {
        // Valeurs par defaut si pas d'arguments
        String inputPath  = "hdfs://hadoop-hdfs:9000/data/cybersecurity/raw/cybersecurity_threat_detection_logs.csv";
        String outputPath = "hdfs://hadoop-hdfs:9000/data/cybersecurity/logs";

        for (int i = 0; i < args.length; i++) {
            if ("--input".equals(args[i]) && i + 1 < args.length)  inputPath  = args[i + 1];
            if ("--output".equals(args[i]) && i + 1 < args.length) outputPath = args[i + 1];
        }

        logger.info("=== ConvertToParquet ===");
        logger.info("Input : {}", inputPath);
        logger.info("Output: {}", outputPath);

        SparkSession spark = SparkConfig.createSession("ConvertToParquet");
        spark.sparkContext().setLogLevel("WARN");

        try {
            Dataset<Row> csv = spark.read()
                    .schema(SCHEMA)
                    .option("header", "true")
                    .option("timestampFormat", "yyyy-MM-dd HH:mm:ss")
                    .csv(inputPath);

            logger.info("Lignes lues depuis CSV: {}", csv.count());
            csv.printSchema();

            // Ajout des colonnes de partitionnement
            Dataset<Row> partitioned = csv
                    .withColumn("year",  year(col("timestamp")).cast("string"))
                    .withColumn("month", lpad(month(col("timestamp")).cast("string"), 2, "0"))
                    .withColumn("day",   lpad(dayofmonth(col("timestamp")).cast("string"), 2, "0"));

            // Ecriture en Parquet avec partitionnement par date
            partitioned.write()
                    .mode("overwrite")
                    .partitionBy("year", "month", "day")
                    .parquet(outputPath);

            logger.info("✅ Conversion terminee. Donnees disponibles dans: {}", outputPath);

        } catch (Exception e) {
            logger.error("Erreur lors de la conversion CSV -> Parquet", e);
            System.exit(1);
        } finally {
            spark.stop();
        }
    }
}
