package com.cybersec.serving.models;

import java.util.List;

/**
 * Reponse fusionnee batch + speed pour une IP.
 *
 * Correspond exactement au format JSON defini dans le PRD :
 * GET /threats/ip/{ip} -> { ip, batch_layer, speed_layer, recommendation, confidence }
 */
public class ThreatProfile {

    private String ip;
    private BatchLayerInfo batchLayer;
    private SpeedLayerInfo speedLayer;
    private String recommendation;   // BLOCK, MONITOR, ALLOW
    private double confidence;       // 0.0 - 1.0

    public ThreatProfile() {}

    public ThreatProfile(String ip) {
        this.ip = ip;
    }

    // ── Classes imbriquees pour la structure JSON ────────────────────

    public static class BatchLayerInfo {
        private long reputationScore;
        private long totalHistoricalEvents;
        private List<String> attackTypesDetected;
        private String firstSeen;
        private String lastBatchUpdate;

        public long getReputationScore() { return reputationScore; }
        public void setReputationScore(long reputationScore) { this.reputationScore = reputationScore; }

        public long getTotalHistoricalEvents() { return totalHistoricalEvents; }
        public void setTotalHistoricalEvents(long totalHistoricalEvents) { this.totalHistoricalEvents = totalHistoricalEvents; }

        public List<String> getAttackTypesDetected() { return attackTypesDetected; }
        public void setAttackTypesDetected(List<String> attackTypesDetected) { this.attackTypesDetected = attackTypesDetected; }

        public String getFirstSeen() { return firstSeen; }
        public void setFirstSeen(String firstSeen) { this.firstSeen = firstSeen; }

        public String getLastBatchUpdate() { return lastBatchUpdate; }
        public void setLastBatchUpdate(String lastBatchUpdate) { this.lastBatchUpdate = lastBatchUpdate; }
    }

    public static class SpeedLayerInfo {
        private int    activeAlerts;
        private String lastSeen;
        private int    currentThreatScore;
        private List<String> recentAttackTypes;
        private long   bytesLastHour;

        public int getActiveAlerts() { return activeAlerts; }
        public void setActiveAlerts(int activeAlerts) { this.activeAlerts = activeAlerts; }

        public String getLastSeen() { return lastSeen; }
        public void setLastSeen(String lastSeen) { this.lastSeen = lastSeen; }

        public int getCurrentThreatScore() { return currentThreatScore; }
        public void setCurrentThreatScore(int currentThreatScore) { this.currentThreatScore = currentThreatScore; }

        public List<String> getRecentAttackTypes() { return recentAttackTypes; }
        public void setRecentAttackTypes(List<String> recentAttackTypes) { this.recentAttackTypes = recentAttackTypes; }

        public long getBytesLastHour() { return bytesLastHour; }
        public void setBytesLastHour(long bytesLastHour) { this.bytesLastHour = bytesLastHour; }
    }

    // ── Getters & Setters principaux ─────────────────────────────────
    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }

    public BatchLayerInfo getBatchLayer() { return batchLayer; }
    public void setBatchLayer(BatchLayerInfo batchLayer) { this.batchLayer = batchLayer; }

    public SpeedLayerInfo getSpeedLayer() { return speedLayer; }
    public void setSpeedLayer(SpeedLayerInfo speedLayer) { this.speedLayer = speedLayer; }

    public String getRecommendation() { return recommendation; }
    public void setRecommendation(String recommendation) { this.recommendation = recommendation; }

    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = confidence; }
}
