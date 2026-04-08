package com.cybersec.serving.models;

import java.util.List;

/**
 * Profil de reputation historique d'une IP (lecture HBase).
 * Alimente par les jobs Spark batch (ip_reputation table).
 */
public class IPReputation {
    private String ip;
    private long   reputationScore;      // 0-100
    private long   totalHistoricalEvents;
    private long   uniqueTargets;
    private long   totalBytes;
    private String firstSeen;
    private String lastBatchUpdate;
    private List<String> attackTypesDetected;
    private String logTypes;

    // Constructeur vide (deserialization)
    public IPReputation() {}

    public IPReputation(String ip) {
        this.ip = ip;
        this.reputationScore = 0;
        this.totalHistoricalEvents = 0;
    }

    // ── Getters & Setters ────────────────────────────────────────────
    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }

    public long getReputationScore() { return reputationScore; }
    public void setReputationScore(long reputationScore) { this.reputationScore = reputationScore; }

    public long getTotalHistoricalEvents() { return totalHistoricalEvents; }
    public void setTotalHistoricalEvents(long totalHistoricalEvents) { this.totalHistoricalEvents = totalHistoricalEvents; }

    public long getUniqueTargets() { return uniqueTargets; }
    public void setUniqueTargets(long uniqueTargets) { this.uniqueTargets = uniqueTargets; }

    public long getTotalBytes() { return totalBytes; }
    public void setTotalBytes(long totalBytes) { this.totalBytes = totalBytes; }

    public String getFirstSeen() { return firstSeen; }
    public void setFirstSeen(String firstSeen) { this.firstSeen = firstSeen; }

    public String getLastBatchUpdate() { return lastBatchUpdate; }
    public void setLastBatchUpdate(String lastBatchUpdate) { this.lastBatchUpdate = lastBatchUpdate; }

    public List<String> getAttackTypesDetected() { return attackTypesDetected; }
    public void setAttackTypesDetected(List<String> attackTypesDetected) { this.attackTypesDetected = attackTypesDetected; }

    public String getLogTypes() { return logTypes; }
    public void setLogTypes(String logTypes) { this.logTypes = logTypes; }
}
