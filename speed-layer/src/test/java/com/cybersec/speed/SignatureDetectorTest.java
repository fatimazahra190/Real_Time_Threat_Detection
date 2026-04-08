package com.cybersec.speed;

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

import static org.apache.spark.sql.functions.*;
import static org.junit.Assert.*;

/**
 * Tests unitaires pour la logique de detection du SignatureDetector.
 */
public class SignatureDetectorTest {

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

    private static final String TOOL_PATTERN =
            "(?i)(sqlmap|nikto|nmap|masscan|burpsuite|dirbuster|hydra|metasploit)";
    private static final String SQLI_PATTERN =
            "(?i)(\\'\\s+OR|UNION\\s+SELECT|1=1--|DROP\\s+TABLE|xp_cmdshell|EXEC\\()";
    private static final String XSS_PATTERN =
            "(?i)(<script|javascript:|onerror=|alert\\(|document\\.cookie)";

    @BeforeClass
    public static void setUp() {
        spark = SparkSession.builder()
                .appName("SignatureDetectorTest")
                .master("local[1]")
                .config("spark.sql.shuffle.partitions", "1")
                .getOrCreate();
        spark.sparkContext().setLogLevel("ERROR");
    }

    @AfterClass
    public static void tearDown() {
        if (spark != null) spark.stop();
    }

    private Dataset<Row> createDataset(List<Row> data) {
        return spark.createDataFrame(data, SCHEMA);
    }

    @Test
    public void testSqlmapDetectedInUserAgent() {
        Timestamp ts = Timestamp.valueOf("2023-10-15 14:00:00");
        List<Row> data = Arrays.asList(
                RowFactory.create(ts, "10.0.0.1", "192.168.1.1", "HTTP", "blocked",
                        "malicious", "ids", 1024L, "sqlmap/1.7.8#stable", "/login.php")
        );

        Dataset<Row> ds = createDataset(data);
        Dataset<Row> matches = ds.filter(col("user_agent").rlike(TOOL_PATTERN))
                .withColumn("alert_type", lit("KNOWN_ATTACK_TOOL"))
                .withColumn("threat_score", lit(95));

        assertEquals("sqlmap doit etre detecte", 1L, matches.count());
        assertEquals("Score = 95 pour outil connu", 95, matches.first().getInt(matches.first().fieldIndex("threat_score")));
    }

    @Test
    public void testNiktoDetected() {
        Timestamp ts = Timestamp.valueOf("2023-10-15 14:00:00");
        List<Row> data = Arrays.asList(
                RowFactory.create(ts, "10.0.0.2", "192.168.1.2", "HTTP", "blocked",
                        "malicious", "ids", 512L, "nikto/2.1.6", "/")
        );
        Dataset<Row> ds = createDataset(data);
        long count = ds.filter(col("user_agent").rlike(TOOL_PATTERN)).count();
        assertEquals("nikto doit etre detecte", 1L, count);
    }

    @Test
    public void testNmapDetected() {
        Timestamp ts = Timestamp.valueOf("2023-10-15 14:00:00");
        List<Row> data = Arrays.asList(
                RowFactory.create(ts, "10.0.0.3", "192.168.1.3", "TCP", "blocked",
                        "malicious", "firewall", 64L, "nmap/7.94 scripting engine", "/")
        );
        Dataset<Row> ds = createDataset(data);
        long count = ds.filter(col("user_agent").rlike(TOOL_PATTERN)).count();
        assertEquals("nmap doit etre detecte", 1L, count);
    }

    @Test
    public void testSQLiInRequestPath() {
        Timestamp ts = Timestamp.valueOf("2023-10-15 14:00:00");
        List<Row> data = Arrays.asList(
                RowFactory.create(ts, "10.0.0.4", "192.168.1.10", "HTTP", "blocked",
                        "malicious", "ids", 2048L, "Mozilla/5.0",
                        "/product?id=1 UNION SELECT username,password FROM users--")
        );
        Dataset<Row> ds = createDataset(data);
        Dataset<Row> matches = ds.filter(col("request_path").rlike(SQLI_PATTERN))
                .withColumn("threat_score", lit(85));
        assertEquals("UNION SELECT detecte dans request_path", 1L, matches.count());
        assertEquals("Score = 85 pour SQLi", 85, matches.first().getInt(matches.first().fieldIndex("threat_score")));
    }

    @Test
    public void testXSSInRequestPath() {
        Timestamp ts = Timestamp.valueOf("2023-10-15 14:00:00");
        List<Row> data = Arrays.asList(
                RowFactory.create(ts, "10.0.0.5", "192.168.1.10", "HTTP", "allowed",
                        "suspicious", "application", 1024L, "Mozilla/5.0",
                        "/search?q=<script>alert(document.cookie)</script>")
        );
        Dataset<Row> ds = createDataset(data);
        long count = ds.filter(col("request_path").rlike(XSS_PATTERN)).count();
        assertEquals("XSS detecte dans request_path", 1L, count);
    }

    @Test
    public void testNormalUserAgentNotFlagged() {
        Timestamp ts = Timestamp.valueOf("2023-10-15 14:00:00");
        List<Row> data = Arrays.asList(
                RowFactory.create(ts, "192.168.1.50", "10.0.0.10", "HTTP", "allowed",
                        "benign", "application", 5000L,
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/118.0",
                        "/index.html"),
                RowFactory.create(ts, "192.168.1.51", "10.0.0.10", "HTTP", "allowed",
                        "benign", "application", 3000L,
                        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)",
                        "/home")
        );
        Dataset<Row> ds = createDataset(data);
        long toolMatches = ds.filter(col("user_agent").rlike(TOOL_PATTERN)).count();
        long sqliMatches = ds.filter(col("request_path").rlike(SQLI_PATTERN)).count();
        long xssMatches  = ds.filter(col("request_path").rlike(XSS_PATTERN)).count();

        assertEquals("User-Agent normal ne doit pas etre flagge (outils)", 0L, toolMatches);
        assertEquals("URL normale ne doit pas etre flaggee (SQLi)", 0L, sqliMatches);
        assertEquals("URL normale ne doit pas etre flaggee (XSS)", 0L, xssMatches);
    }
}
