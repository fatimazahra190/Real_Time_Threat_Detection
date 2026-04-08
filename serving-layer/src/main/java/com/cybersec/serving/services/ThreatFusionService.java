package com.cybersec.serving.services;

import com.cybersec.serving.models.ActiveAlert;
import com.cybersec.serving.models.IPReputation;
import com.cybersec.serving.models.ThreatProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Service de fusion batch + speed.
 *
 * Combine les donnees historiques (HBase) et temps reel (Cassandra)
 * pour produire un profil complet de menace et une recommandation.
 *
 * Logique de recommandation (PRD Section 5.1.3) :
 *   - Score batch > 80 ET alertes actives >= 1  -> BLOCK
 *   - Score batch entre 50 et 80                -> MONITOR
 *   - Score batch < 50 ET aucune alerte active  -> ALLOW
 *
 * Calcul de confidence :
 *   confidence = (batch_score * 0.4 + speed_score * 0.6) / 100
 */
@Service
public class ThreatFusionService {

    private static final Logger logger = LoggerFactory.getLogger(ThreatFusionService.class);

    @Autowired
    private HBaseService hbaseService;

    @Autowired
    private CassandraService cassandraService;

    /**
     * Construit le profil complet de menace pour une IP.
     * Consultation parallele HBase + Cassandra, puis fusion.
     *
     * @param ip Adresse IP a analyser
     * @return ThreatProfile fusionne avec recommandation
     */
    public ThreatProfile getThreatProfile(String ip) {
        logger.info("Construction du profil de menace pour IP: {}", ip);

        // ── Lecture batch (HBase) ────────────────────────────────────
        IPReputation batchData   = hbaseService.getIPReputation(ip);
        List<String> attackTypes = hbaseService.getAttackTypes(ip);
        batchData.setAttackTypesDetected(attackTypes);

        // ── Lecture speed (Cassandra) ────────────────────────────────
        List<ActiveAlert> activeAlerts   = cassandraService.getActiveAlerts(ip);
        int  currentScore                = cassandraService.getCurrentThreatScore(ip);
        long bytesTotal                  = cassandraService.getBytesTotal(ip);
        List<String> recentAttackTypes   = cassandraService.getRecentAttackTypes(ip);

        // ── Construction du profil ───────────────────────────────────
        ThreatProfile profile = new ThreatProfile(ip);

        // Batch Layer
        ThreatProfile.BatchLayerInfo batchInfo = new ThreatProfile.BatchLayerInfo();
        batchInfo.setReputationScore(batchData.getReputationScore());
        batchInfo.setTotalHistoricalEvents(batchData.getTotalHistoricalEvents());
        batchInfo.setAttackTypesDetected(batchData.getAttackTypesDetected());
        batchInfo.setFirstSeen(batchData.getFirstSeen());
        batchInfo.setLastBatchUpdate(batchData.getLastBatchUpdate());
        profile.setBatchLayer(batchInfo);

        // Speed Layer
        ThreatProfile.SpeedLayerInfo speedInfo = new ThreatProfile.SpeedLayerInfo();
        speedInfo.setActiveAlerts(activeAlerts.size());
        speedInfo.setCurrentThreatScore(currentScore);
        speedInfo.setRecentAttackTypes(recentAttackTypes);
        speedInfo.setBytesLastHour(bytesTotal);
        if (!activeAlerts.isEmpty()) {
            speedInfo.setLastSeen(activeAlerts.get(0).getLastSeen());
        }
        profile.setSpeedLayer(speedInfo);

        // ── Recommandation ───────────────────────────────────────────
        String recommendation = computeRecommendation(
                batchData.getReputationScore(),
                activeAlerts.size()
        );
        profile.setRecommendation(recommendation);

        // ── Confidence ───────────────────────────────────────────────
        double confidence = computeConfidence(
                batchData.getReputationScore(),
                currentScore
        );
        profile.setConfidence(confidence);

        logger.info("Profil IP {} -> score_batch={} | alertes={} | recommandation={} | confidence={}",
                ip,
                batchData.getReputationScore(),
                activeAlerts.size(),
                recommendation,
                String.format("%.2f", confidence)
        );

        return profile;
    }

    /**
     * Logique de recommandation selon le PRD (Section 5.1.3).
     *
     * @param batchScore   Score historique HBase (0-100)
     * @param activeAlerts Nombre d'alertes actives Cassandra
     * @return "BLOCK", "MONITOR", ou "ALLOW"
     */
    public String computeRecommendation(long batchScore, int activeAlerts) {
        if (batchScore > 80 && activeAlerts >= 1) {
            return "BLOCK";
        } else if (batchScore >= 50) {
            return "MONITOR";
        } else if (activeAlerts > 0) {
            // IP inconnue du batch mais presente en temps reel -> surveiller
            return "MONITOR";
        } else {
            return "ALLOW";
        }
    }

    /**
     * Calcul du score de confiance.
     * Poids : batch 40%, speed 60% (le temps reel est plus fiable).
     *
     * @param batchScore Score batch (0-100)
     * @param speedScore Score speed (0-100)
     * @return Confidence de 0.0 a 1.0
     */
    public double computeConfidence(long batchScore, int speedScore) {
        double weighted = (batchScore * 0.4) + (speedScore * 0.6);
        return Math.min(1.0, Math.round(weighted) / 100.0);
    }
}
