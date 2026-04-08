package com.cybersec.serving;

import com.cybersec.serving.models.ActiveAlert;
import com.cybersec.serving.models.IPReputation;
import com.cybersec.serving.models.ThreatProfile;
import com.cybersec.serving.services.CassandraService;
import com.cybersec.serving.services.HBaseService;
import com.cybersec.serving.services.ThreatFusionService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Tests unitaires pour ThreatFusionService.
 * Utilise Mockito pour simuler HBaseService et CassandraService
 * sans infrastructure reelle.
 */
@RunWith(MockitoJUnitRunner.class)
public class ThreatFusionServiceTest {

    @Mock
    private HBaseService hbaseService;

    @Mock
    private CassandraService cassandraService;

    @InjectMocks
    private ThreatFusionService threatFusionService;

    private static final String TEST_IP = "192.168.1.45";

    // ── Setup ────────────────────────────────────────────────────────

    private IPReputation createReputation(long score, long events) {
        IPReputation rep = new IPReputation(TEST_IP);
        rep.setReputationScore(score);
        rep.setTotalHistoricalEvents(events);
        rep.setUniqueTargets(10);
        rep.setLastBatchUpdate("2023-10-14T23:00:00Z");
        return rep;
    }

    private ActiveAlert createAlert(String type, String severity, int score) {
        ActiveAlert alert = new ActiveAlert();
        alert.setIpSource(TEST_IP);
        alert.setAlertType(type);
        alert.setSeverity(severity);
        alert.setThreatScore(score);
        alert.setEventCount(5);
        alert.setBytesTotal(1024L);
        alert.setLastSeen("2023-10-15T14:23:45Z");
        return alert;
    }

    // ── Tests recommandation BLOCK ───────────────────────────────────

    @Test
    public void testRecommendationBLOCK_HighScoreWithAlerts() {
        // Score batch = 87 (> 80) ET 3 alertes actives -> BLOCK
        IPReputation rep = createReputation(87, 1243);
        List<ActiveAlert> alerts = Arrays.asList(
                createAlert("BRUTE_FORCE", "CRITICAL", 92),
                createAlert("SQLI_DETECTED", "CRITICAL", 85),
                createAlert("TOOL_DETECTED", "CRITICAL", 95)
        );

        when(hbaseService.getIPReputation(TEST_IP)).thenReturn(rep);
        when(hbaseService.getAttackTypes(TEST_IP)).thenReturn(Arrays.asList("BRUTE_FORCE", "SQLI"));
        when(cassandraService.getActiveAlerts(TEST_IP)).thenReturn(alerts);
        when(cassandraService.getCurrentThreatScore(TEST_IP)).thenReturn(92);
        when(cassandraService.getBytesTotal(TEST_IP)).thenReturn(52428800L);
        when(cassandraService.getRecentAttackTypes(TEST_IP)).thenReturn(Arrays.asList("BRUTE_FORCE", "TOOL_DETECTED"));

        ThreatProfile profile = threatFusionService.getThreatProfile(TEST_IP);

        assertEquals("Recommandation doit etre BLOCK", "BLOCK", profile.getRecommendation());
        assertEquals("IP correcte", TEST_IP, profile.getIp());
        assertEquals("Score batch correct", 87L, profile.getBatchLayer().getReputationScore());
        assertEquals("3 alertes actives", 3, profile.getSpeedLayer().getActiveAlerts());
        assertTrue("Confidence > 0.8", profile.getConfidence() > 0.8);
    }

    @Test
    public void testRecommendationBLOCK_ScoreExactly81() {
        // Score batch = 81 (> 80) ET 1 alerte -> BLOCK
        String recommendation = threatFusionService.computeRecommendation(81L, 1);
        assertEquals("BLOCK", recommendation);
    }

    // ── Tests recommandation MONITOR ─────────────────────────────────

    @Test
    public void testRecommendationMONITOR_MediumScoreNoAlerts() {
        // Score batch = 65 (entre 50 et 80) ET 0 alertes -> MONITOR
        String recommendation = threatFusionService.computeRecommendation(65L, 0);
        assertEquals("MONITOR", recommendation);
    }

    @Test
    public void testRecommendationMONITOR_HighScoreButNoAlerts() {
        // Score batch = 85 mais 0 alertes actives -> MONITOR
        // (le scoring batch seul ne suffit pas pour BLOCK)
        String recommendation = threatFusionService.computeRecommendation(85L, 0);
        assertEquals("MONITOR", recommendation);
    }

    @Test
    public void testRecommendationMONITOR_ScoreExactly50() {
        String recommendation = threatFusionService.computeRecommendation(50L, 0);
        assertEquals("MONITOR", recommendation);
    }

    // ── Tests recommandation ALLOW ───────────────────────────────────

    @Test
    public void testRecommendationALLOW_LowScoreNoAlerts() {
        // Score batch = 0, aucune alerte -> ALLOW
        IPReputation rep = createReputation(0, 0);
        List<ActiveAlert> noAlerts = Collections.emptyList();

        when(hbaseService.getIPReputation(TEST_IP)).thenReturn(rep);
        when(hbaseService.getAttackTypes(TEST_IP)).thenReturn(Collections.emptyList());
        when(cassandraService.getActiveAlerts(TEST_IP)).thenReturn(noAlerts);
        when(cassandraService.getCurrentThreatScore(TEST_IP)).thenReturn(0);
        when(cassandraService.getBytesTotal(TEST_IP)).thenReturn(0L);
        when(cassandraService.getRecentAttackTypes(TEST_IP)).thenReturn(Collections.emptyList());

        ThreatProfile profile = threatFusionService.getThreatProfile(TEST_IP);

        assertEquals("Recommandation doit etre ALLOW", "ALLOW", profile.getRecommendation());
        assertEquals("Score batch = 0", 0L, profile.getBatchLayer().getReputationScore());
        assertEquals("0 alertes actives", 0, profile.getSpeedLayer().getActiveAlerts());
        assertEquals("Confidence = 0.0", 0.0, profile.getConfidence(), 0.01);
    }

    @Test
    public void testRecommendationALLOW_ScoreBelow50() {
        String recommendation = threatFusionService.computeRecommendation(49L, 0);
        assertEquals("ALLOW", recommendation);
    }

    // ── Tests confidence ─────────────────────────────────────────────

    @Test
    public void testConfidenceCalculation() {
        // confidence = (batch*0.4 + speed*0.6) / 100
        // batch=80, speed=100 -> (32 + 60) / 100 = 0.92
        double confidence = threatFusionService.computeConfidence(80L, 100);
        assertEquals(0.92, confidence, 0.01);
    }

    @Test
    public void testConfidenceCappedAt1() {
        // Ne doit jamais depasser 1.0
        double confidence = threatFusionService.computeConfidence(100L, 100);
        assertTrue("Confidence <= 1.0", confidence <= 1.0);
    }

    @Test
    public void testConfidenceZeroWhenNoData() {
        double confidence = threatFusionService.computeConfidence(0L, 0);
        assertEquals(0.0, confidence, 0.001);
    }

    // ── Tests structure du profil ────────────────────────────────────

    @Test
    public void testProfileContainsBothLayers() {
        IPReputation rep = createReputation(60, 500);
        List<ActiveAlert> alerts = Collections.singletonList(
                createAlert("BRUTE_FORCE", "HIGH", 75)
        );

        when(hbaseService.getIPReputation(TEST_IP)).thenReturn(rep);
        when(hbaseService.getAttackTypes(TEST_IP)).thenReturn(Collections.singletonList("BRUTE_FORCE"));
        when(cassandraService.getActiveAlerts(TEST_IP)).thenReturn(alerts);
        when(cassandraService.getCurrentThreatScore(TEST_IP)).thenReturn(75);
        when(cassandraService.getBytesTotal(TEST_IP)).thenReturn(2048L);
        when(cassandraService.getRecentAttackTypes(TEST_IP)).thenReturn(Collections.singletonList("BRUTE_FORCE"));

        ThreatProfile profile = threatFusionService.getThreatProfile(TEST_IP);

        assertNotNull("batch_layer ne doit pas etre null", profile.getBatchLayer());
        assertNotNull("speed_layer ne doit pas etre null", profile.getSpeedLayer());
        assertNotNull("recommendation ne doit pas etre null", profile.getRecommendation());
        assertEquals("1 alerte active", 1, profile.getSpeedLayer().getActiveAlerts());
        assertEquals("Score batch = 60", 60L, profile.getBatchLayer().getReputationScore());
    }
}
