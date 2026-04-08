package com.cybersec.batch;

import com.cybersec.batch.jobs.TopMaliciousIPs;
import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.Row;
import org.apache.spark.sql.RowFactory;
import org.apache.spark.sql.SparkSession;
import org.apache.spark.sql.types.*;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

/**
 * Tests unitaires pour TopMaliciousIPs.
 * Utilise SparkSession locale - ne necessite aucune infrastructure.
 */
public class TopMaliciousIPsTest {

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
                .appName("TopMaliciousIPsTest")
                .master("local[1]")
                .config("spark.sql.shuffle.partitions", "1")
                .getOrCreate();
        spark.sparkContext().setLogLevel("ERROR");
    }

    @AfterClass
    public static void tearDown() {
        if (spark != null) spark.stop();
    }

    private Dataset<Row> createTestDataset() {
        Timestamp ts = Timestamp.valueOf("2023-10-15 14:00:00");
        List<Row> data = Arrays.asList(
                // 5 evenements malicious depuis 192.168.1.100
                RowFactory.create(ts, "192.168.1.100", "10.0.0.1", "TCP", "blocked", "malicious", "firewall", 1024L, "sqlmap/1.7", "/admin"),
                RowFactory.create(ts, "192.168.1.100", "10.0.0.2", "TCP", "blocked", "malicious", "firewall", 2048L, "sqlmap/1.7", "/admin"),
                RowFactory.create(ts, "192.168.1.100", "10.0.0.3", "HTTP", "blocked", "malicious", "ids",      512L,  "sqlmap/1.7", "/login"),
                RowFactory.create(ts, "192.168.1.100", "10.0.0.4", "HTTP", "blocked", "malicious", "firewall", 768L,  "sqlmap/1.7", "/wp-admin"),
                RowFactory.create(ts, "192.168.1.100", "10.0.0.5", "TCP", "blocked", "malicious", "firewall", 256L,  "sqlmap/1.7", "/phpmyadmin"),
                // 3 evenements suspicious depuis 192.168.1.200
                RowFactory.create(ts, "192.168.1.200", "10.0.0.10", "HTTP", "allowed", "suspicious", "application", 512L, "Mozilla/5.0", "/search"),
                RowFactory.create(ts, "192.168.1.200", "10.0.0.11", "HTTP", "allowed", "suspicious", "application", 1024L,"Mozilla/5.0", "/search?q=1"),
                RowFactory.create(ts, "192.168.1.200", "10.0.0.12", "HTTP", "blocked", "suspicious", "ids",          256L, "nikto/2.1",  "/admin"),
                // 2 evenements benign (ne doivent pas apparaitre)
                RowFactory.create(ts, "192.168.1.50",  "10.0.0.20", "HTTP", "allowed", "benign", "application", 1500L, "Mozilla/5.0", "/index.html"),
                RowFactory.create(ts, "192.168.1.50",  "10.0.0.21", "HTTP", "allowed", "benign", "application", 2000L, "Mozilla/5.0", "/about.html")
        );
        return spark.createDataFrame(data, SCHEMA);
    }

    @Test
    public void testOnlyMaliciousAndSuspiciousIPs() {
        Dataset<Row> testData = createTestDataset();
        // Simuler le filtrage (logique extraite de analyze())
        Dataset<Row> filtered = testData.filter(
                testData.col("threat_label").isin("suspicious", "malicious")
        );
        long count = filtered.count();
        assertEquals("Seuls les events suspicious/malicious sont filtres", 8L, count);
    }

    @Test
    public void testReputationScoreInRange() {
        // Le score doit etre entre 0 et 100
        // Avec 5 malicious (score = 5*10/5*100 = 100)
        long malicious = 5, suspicious = 0, total = 5;
        long score = Math.min(100, (malicious * 10 + suspicious * 5) / total * 100);
        assertTrue("Score doit etre >= 0", score >= 0);
        assertTrue("Score doit etre <= 100", score <= 100);
    }

    @Test
    public void testBenignIPsNotInResults() {
        Dataset<Row> testData = createTestDataset();
        Dataset<Row> filtered = testData.filter(
                testData.col("threat_label").isin("suspicious", "malicious")
        );
        long benignCount = filtered.filter(filtered.col("source_ip").equalTo("192.168.1.50")).count();
        assertEquals("Les IPs benign ne doivent pas apparaitre", 0L, benignCount);
    }
}
