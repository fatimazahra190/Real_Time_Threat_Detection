package com.cybersec.serving.models;

import java.util.Set;

/**
 * Alerte active en temps reel (lecture Cassandra, TTL 24h).
 * Correspond a une ligne de la table cybersecurity.active_threats.
 */
public class ActiveAlert {
    private String ipSource;
    private String bucketTime;
    private String alertId;
    private String lastSeen;
    private int    threatScore;      // 0-100
    private Set<String> attackTypes;
    private String alertType;
    private String severity;         // LOW, MEDIUM, HIGH, CRITICAL
    private int    eventCount;
    private long   bytesTotal;
    private Set<String> userAgents;
    private Set<String> logSources;

    public ActiveAlert() {}

    // ── Getters & Setters ────────────────────────────────────────────
    public String getIpSource() { return ipSource; }
    public void setIpSource(String ipSource) { this.ipSource = ipSource; }

    public String getBucketTime() { return bucketTime; }
    public void setBucketTime(String bucketTime) { this.bucketTime = bucketTime; }

    public String getAlertId() { return alertId; }
    public void setAlertId(String alertId) { this.alertId = alertId; }

    public String getLastSeen() { return lastSeen; }
    public void setLastSeen(String lastSeen) { this.lastSeen = lastSeen; }

    public int getThreatScore() { return threatScore; }
    public void setThreatScore(int threatScore) { this.threatScore = threatScore; }

    public Set<String> getAttackTypes() { return attackTypes; }
    public void setAttackTypes(Set<String> attackTypes) { this.attackTypes = attackTypes; }

    public String getAlertType() { return alertType; }
    public void setAlertType(String alertType) { this.alertType = alertType; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public int getEventCount() { return eventCount; }
    public void setEventCount(int eventCount) { this.eventCount = eventCount; }

    public long getBytesTotal() { return bytesTotal; }
    public void setBytesTotal(long bytesTotal) { this.bytesTotal = bytesTotal; }

    public Set<String> getUserAgents() { return userAgents; }
    public void setUserAgents(Set<String> userAgents) { this.userAgents = userAgents; }

    public Set<String> getLogSources() { return logSources; }
    public void setLogSources(Set<String> logSources) { this.logSources = logSources; }
}
