package com.cybersec.batch.jobs;

import com.cybersec.batch.config.SparkConfig;
import com.cybersec.batch.utils.HBaseWriter;
import org.apache.spark.sql.Column;
import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.Row;
import org.apache.spark.sql.SparkSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.spark.sql.functions.*;

/**
 * Job Spark #3 — Detection des patterns SQLi, XSS, LFI et outils malveillants.
 *
 * Analyse les champs request_path et user_agent pour detecter :
 * - Injections SQL (SQLi) dans les URL
 * - Cross-Site Scripting (XSS) dans les URL
 * - Local File Inclusion (LFI) : traversal de repertoire
 * - Outils d'attaque connus dans le User-Agent (sqlmap, nikto, etc.)
 *
 * Referentiel : OWASP Top 10 A03 (Injection) et Sigma Rules.
 */
public class AttackPatternDetector {

    private static final Logger logger = LoggerFactory.getLogger(AttackPatternDetector.class);

    // ── Patterns OWASP / Sigma Rules ──────────────────────────────
    // Injection SQL : mots-cles SQL malveillants dans l'URL
    public static final String SQLI_PATTERN =
            "(?i)(\\'\\s+OR|UNION\\s+SELECT|1=1--|DROP\\s+TABLE|xp_cmdshell|EXEC\\(|INSERT\\s+INTO|DELETE\\s+FROM)";

    // Cross-Site Scripting : balises et attributs JS dangereux
    public static final String XSS_PATTERN =
            "(?i)(<script|javascript:|onerror=|alert\\(|document\\.cookie|eval\\(|onload=)";

    // Local File Inclusion : traversal de repertoire
    public static final String LFI_PATTERN =
            "(?i)(\\.\\./\\.\\./|/etc/passwd|/etc/shadow|/proc/self|%2e%2e%2f)";

    // Outils d'attaque connus dans le User-Agent
    public static final String TOOL_PATTERN =
            "(?i)(sqlmap|nikto|nmap|masscan|burpsuite|dirbuster|hydra|metasploit|w3af|acunetix|openvas)";

    public static void main(String[] args) {
        logger.info("=== Demarrage Job: Detection Patterns Attaques ===");

        SparkSession spark = SparkConfig.createSession("AttackPatternDetector");
        spark.sparkContext().setLogLevel("WARN");

        try {
            Dataset<Row> result = detect(spark);

            result.show(20, false);
            logger.info("Distribution des categories d'attaques detectees:");
            result.groupBy("attack_category").count().show();

            String outputPath = SparkConfig.hdfsPath("/data/cybersecurity/batch/attack_patterns");
            result.write().mode("overwrite").parquet(outputPath);
            logger.info("Resultats sauvegardes: {}", outputPath);

            HBaseWriter.writeAttackPattern(result, "INJECTION");

            logger.info("=== Job AttackPatternDetector termine: {} attaques detectees ===",
                    result.count());

        } catch (Exception e) {
            logger.error("Erreur dans AttackPatternDetector", e);
            System.exit(1);
        } finally {
            spark.stop();
        }
    }

    /**
     * Logique de detection des patterns d'attaque.
     */
    public static Dataset<Row> detect(SparkSession spark) {
        String inputPath = SparkConfig.hdfsPath("/data/cybersecurity/logs/*/*/*");
        Dataset<Row> logs = spark.read().parquet(inputPath);

        // Colonnes de detection par type
        Column sqliMatch = col("request_path").rlike(SQLI_PATTERN);
        Column xssMatch  = col("request_path").rlike(XSS_PATTERN);
        Column lfiMatch  = col("request_path").rlike(LFI_PATTERN);
        Column toolMatch = col("user_agent").rlike(TOOL_PATTERN);

        return logs
                // Garder uniquement les lignes qui matchent au moins un pattern
                .filter(sqliMatch.or(xssMatch).or(lfiMatch).or(toolMatch))
                // Ajouter les colonnes de correspondance booleennes
                .withColumn("is_sqli", sqliMatch)
                .withColumn("is_xss",  xssMatch)
                .withColumn("is_lfi",  lfiMatch)
                .withColumn("is_tool", toolMatch)
                // Categoriser par type d'attaque principal (priorite : outil > sqli > xss > lfi)
                .withColumn("attack_category",
                    when(toolMatch, "TOOL_DETECTED")
                    .when(sqliMatch, "SQLI")
                    .when(xssMatch,  "XSS")
                    .when(lfiMatch,  "LFI")
                    .otherwise("UNKNOWN")
                )
                // Attribuer un score selon la gravite
                .withColumn("threat_score",
                    when(toolMatch, 95)
                    .when(sqliMatch, 85)
                    .when(xssMatch,  75)
                    .when(lfiMatch,  70)
                    .otherwise(60)
                )
                .withColumn("severity", lit("CRITICAL"))
                .orderBy(col("threat_score").desc(), col("timestamp").desc());
    }
}
