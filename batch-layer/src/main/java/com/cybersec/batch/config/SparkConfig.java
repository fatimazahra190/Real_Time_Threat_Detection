package com.cybersec.batch.config;

import org.apache.spark.sql.SparkSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Configuration centralisee de SparkSession pour la couche batch.
 * Lit les variables d'environnement pour s'adapter au mode solo ou cluster.
 */
public class SparkConfig {

    private static final Logger logger = LoggerFactory.getLogger(SparkConfig.class);

    private static final String HDFS_HOST = System.getenv().getOrDefault("HDFS_NAMENODE_HOST", "hadoop-hdfs");
    private static final String HDFS_PORT = System.getenv().getOrDefault("HDFS_PORT", "9000");
    private static final String HBASE_HOST = System.getenv().getOrDefault("HBASE_HOST", "hbase");
    private static final String ZOOKEEPER_HOST = System.getenv().getOrDefault("ZOOKEEPER_HOST", "zookeeper");

    /**
     * Cree et configure une SparkSession pour les jobs batch.
     *
     * @param appName Nom de l'application Spark (visible dans le Spark UI)
     * @return SparkSession configuree
     */
    public static SparkSession createSession(String appName) {
        logger.info("Creation SparkSession pour '{}' | HDFS: {}:{} | HBase: {}",
                appName, HDFS_HOST, HDFS_PORT, HBASE_HOST);

        return SparkSession.builder()
                .appName(appName)
                .master("local[*]")
                // Configuration HDFS
                .config("spark.hadoop.fs.defaultFS", "hdfs://" + HDFS_HOST + ":" + HDFS_PORT)
                // Configuration HBase via ZooKeeper
                .config("hbase.zookeeper.quorum", ZOOKEEPER_HOST)
                .config("hbase.zookeeper.property.clientPort", "2181")
                // Performances
                .config("spark.sql.shuffle.partitions", "4")
                .config("spark.network.timeout", "300s")
                .config("spark.executor.heartbeatInterval", "60s")
                // Eviter les logs trop verbeux
                .config("spark.ui.showConsoleProgress", "false")
                .getOrCreate();
    }

    /**
     * Construit un chemin HDFS absolu a partir d'un chemin relatif.
     *
     * @param relativePath Chemin relatif (ex: "/data/cybersecurity/logs")
     * @return Chemin HDFS complet (ex: "hdfs://hadoop-hdfs:9000/data/cybersecurity/logs")
     */
    public static String hdfsPath(String relativePath) {
        return "hdfs://" + HDFS_HOST + ":" + HDFS_PORT + relativePath;
    }

    public static String getHbaseHost() {
        return HBASE_HOST;
    }

    public static String getZookeeperHost() {
        return ZOOKEEPER_HOST;
    }
}
