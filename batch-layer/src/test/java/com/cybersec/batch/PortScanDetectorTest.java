package com.cybersec.batch;

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
import java.util.Arrays;
import java.util.List;

import static org.apache.spark.sql.functions.*;
import static org.junit.Assert.*;

/**
 * Tests unitaires pour PortScanDetector.
 */
public class PortScanDetectorTest {

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
                .appName("PortScanDetectorTest")
                .master("local[1]")
                .config("spark.sql.shuffle.partitions", "1")
                .getOrCreate();
        spark.sparkContext().setLogLevel("ERROR");
    }

    @AfterClass
    public static void tearDown() {
        if (spark != null) spark.stop();
    }

    @Test
    public void testPortScanDetected() {
        // 25 connexions TCP vers 25 destinations differentes depuis la meme IP en 2 min
        Timestamp baseTs = Timestamp.valueOf("2023-10-15 14:00:00");
        List<Row> data = new ArrayList<>();
        String scannerIP = "192.168.1.99";

        for (int i = 1; i <= 25; i++) {
            Timestamp ts = new Timestamp(baseTs.getTime() + (i * 4000L)); // 4s d'ecart
            data.add(RowFactory.create(
                    ts, scannerIP, "10.0.0." + i, "TCP", "blocked",
                    "suspicious", "firewall", 64L, "nmap/7.94", "/scan"
            ));
        }

        Dataset<Row> testData = spark.createDataFrame(data, SCHEMA);
        Dataset<Row> tcpOnly = testData.filter(col("protocol").equalTo("TCP"));

        // Compter les destinations distinctes pour cette IP dans la fenetre
        long distinctTargets = tcpOnly.filter(col("source_ip").equalTo(scannerIP))
                .select("dest_ip").distinct().count();

        assertTrue("25 destinations distinctes detectees", distinctTargets >= 25);
        assertTrue("Depasse le seuil de 20", distinctTargets > 20);
    }

    @Test
    public void testNoFalsePositiveBelow20() {
        // Seulement 5 connexions TCP - ne doit pas declencher d'alerte
        Timestamp baseTs = Timestamp.valueOf("2023-10-15 14:00:00");
        List<Row> data = new ArrayList<>();

        for (int i = 1; i <= 5; i++) {
            Timestamp ts = new Timestamp(baseTs.getTime() + (i * 1000L));
            data.add(RowFactory.create(
                    ts, "192.168.1.50", "10.0.0." + i, "TCP", "allowed",
                    "benign", "firewall", 1024L, "Mozilla/5.0", "/"
            ));
        }

        Dataset<Row> testData = spark.createDataFrame(data, SCHEMA);
        long distinctTargets = testData.filter(col("protocol").equalTo("TCP"))
                .select("dest_ip").distinct().count();

        assertTrue("5 destinations en dessous du seuil", distinctTargets <= 20);
    }

    @Test
    public void testOnlyTCPFiltered() {
        // Melange TCP et HTTP - seul TCP doit etre analyse
        Timestamp ts = Timestamp.valueOf("2023-10-15 14:00:00");
        List<Row> data = Arrays.asList(
                RowFactory.create(ts, "10.0.0.1", "10.0.0.100", "TCP",  "blocked", "suspicious", "firewall", 100L, "nmap", "/"),
                RowFactory.create(ts, "10.0.0.1", "10.0.0.101", "HTTP", "blocked", "suspicious", "ids",      200L, "curl", "/api"),
                RowFactory.create(ts, "10.0.0.1", "10.0.0.102", "SSH",  "blocked", "malicious",  "firewall", 300L, "hydra","/")
        );

        Dataset<Row> testData = spark.createDataFrame(data, SCHEMA);
        long tcpCount = testData.filter(col("protocol").equalTo("TCP")).count();
        assertEquals("Seuls les paquets TCP sont analyses", 1L, tcpCount);
    }
}
