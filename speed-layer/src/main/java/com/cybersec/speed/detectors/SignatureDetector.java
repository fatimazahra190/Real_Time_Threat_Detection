package com.cybersec.speed.detectors;

import com.cybersec.speed.utils.CassandraWriter;
import org.apache.spark.sql.Column;
import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.Row;
import org.apache.spark.sql.streaming.StreamingQuery;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.spark.sql.functions.*;

/**
 * Detecteur de signatures malveillantes en temps reel.
 *
 * Analyse user_agent et request_path pour identifier :
 * - Outils d'attaque connus (sqlmap, nikto, nmap, hydra, metasploit...)
 * - Injections SQL dans l'URL
 * - XSS dans l'URL
 * - LFI / traversal de repertoire
 *
 * Score : 95 (outil), 85 (SQLi), 75 (XSS/LFI).
 * Severite : CRITICAL pour tous (action immediate requise).
 * Reference : OWASP Top 10 A03, Sigma Rules web_attack_sql_injection.
 */
public class SignatureDetector {

    private static final Logger logger = LoggerFactory.getLogger(SignatureDetector.class);

    private static final String CHECKPOINT = "/tmp/checkpoint/signatures";

    // Patterns identiques au batch pour coherence
    private static final String TOOL_PATTERN =
            "(?i)(sqlmap|nikto|nmap|masscan|burpsuite|dirbuster|hydra|metasploit|w3af|acunetix|openvas)";
    private static final String SQLI_PATTERN =
            "(?i)(\\'\\s+OR|UNION\\s+SELECT|1=1--|DROP\\s+TABLE|xp_cmdshell|EXEC\\(|INSERT\\s+INTO)";
    private static final String XSS_PATTERN =
            "(?i)(<script|javascript:|onerror=|alert\\(|document\\.cookie|eval\\()";
    private static final String LFI_PATTERN =
            "(?i)(\\.\\./\\.\\./|/etc/passwd|/etc/shadow|%2e%2e%2f)";

    /**
     * Lance le stream de detection de signatures.
     *
     * @param stream Dataset<Row> depuis Kafka
     * @return StreamingQuery active
     */
    public static StreamingQuery detect(Dataset<Row> stream) {
        logger.info("Demarrage detecteur SignatureDetector");

        Column toolMatch = col("user_agent").rlike(TOOL_PATTERN);
        Column sqliMatch = col("request_path").rlike(SQLI_PATTERN);
        Column xssMatch  = col("request_path").rlike(XSS_PATTERN);
        Column lfiMatch  = col("request_path").rlike(LFI_PATTERN);

        Dataset<Row> alerts = stream
                .filter(toolMatch.or(sqliMatch).or(xssMatch).or(lfiMatch))
                .withColumn("alert_type",
                    when(toolMatch, "KNOWN_ATTACK_TOOL")
                    .when(sqliMatch, "SQLI_DETECTED")
                    .when(xssMatch,  "XSS_DETECTED")
                    .when(lfiMatch,  "LFI_DETECTED")
                    .otherwise("SIGNATURE_MATCH")
                )
                .withColumn("threat_score",
                    when(toolMatch, 95)
                    .when(sqliMatch, 85)
                    .when(xssMatch,  75)
                    .when(lfiMatch,  70)
                    .otherwise(60)
                )
                .withColumn("severity", lit("CRITICAL"))
                .withColumn("event_count", lit(1))
                .withColumn("bytes_total", col("bytes_transferred"));

        return alerts.writeStream()
                .outputMode("append")
                .option("checkpointLocation", CHECKPOINT)
                .foreachBatch((batchDF, batchId) -> {
                    long alertCount = batchDF.count();
                    if (alertCount > 0) {
                        logger.warn("Batch {} - {} signatures malveillantes detectees", batchId, alertCount);
                        batchDF.show(false);
                        batchDF.foreach(row -> CassandraWriter.writeFromRow(row));
                    }
                })
                .start();
    }
}
