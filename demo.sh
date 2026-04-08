#!/bin/bash
# demo.sh — Script de demonstration end-to-end
# Lance un scenario d'attaque et montre les alertes apparaitre dans l'API
# Duree estimee : 2-3 minutes

set -e

API_URL="http://localhost:8080"
KAFKA_CONTAINER="kafka"

echo "============================================"
echo "  Demo End-to-End — CyberSec Lambda System"
echo "============================================"
echo ""

# ── Verification que l'infrastructure est up ─────────────────────────
echo "🔍 Verification de l'infrastructure..."
if ! curl -s "${API_URL}/health" | grep -q '"status"'; then
    echo "❌ L'API REST n'est pas accessible sur ${API_URL}"
    echo "   Lancer d'abord: docker compose up -d && ./init.sh"
    exit 1
fi
echo "✅ API REST accessible"

# ── Etape 1 : Scenario Brute-Force ───────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  SCENARIO 1 : Attaque Brute-Force"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "   Publication de 8 connexions bloquees depuis 10.10.10.1..."
echo "   Seuil de detection : 5 tentatives en 1 minute"
echo ""

NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
for i in $(seq 1 8); do
    MSG="{\"timestamp\":\"${NOW}\",\"source_ip\":\"10.10.10.1\",\"dest_ip\":\"192.168.0.10\",\"protocol\":\"HTTP\",\"action\":\"blocked\",\"threat_label\":\"malicious\",\"log_type\":\"firewall\",\"bytes_transferred\":512,\"user_agent\":\"hydra/9.4\",\"request_path\":\"/admin/login\"}"
    echo "${MSG}" | docker exec -i ${KAFKA_CONTAINER} \
        kafka-console-producer.sh \
        --bootstrap-server localhost:9092 \
        --topic cybersecurity-logs \
        --property "key.separator=:" \
        --property "parse.key=false" 2>/dev/null
    echo "   Tentative ${i}/8 envoyee -> 10.10.10.1 | action=blocked"
    sleep 0.5
done

# ── Etape 2 : Scenario SQLi ──────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  SCENARIO 2 : Injection SQL via sqlmap"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

SQLI_MSG="{\"timestamp\":\"${NOW}\",\"source_ip\":\"10.20.30.40\",\"dest_ip\":\"192.168.0.20\",\"protocol\":\"HTTP\",\"action\":\"blocked\",\"threat_label\":\"malicious\",\"log_type\":\"ids\",\"bytes_transferred\":2048,\"user_agent\":\"sqlmap/1.7.8#stable\",\"request_path\":\"/product.php?id=1' OR '1'='1\"}"
echo "${SQLI_MSG}" | docker exec -i ${KAFKA_CONTAINER} \
    kafka-console-producer.sh \
    --bootstrap-server localhost:9092 \
    --topic cybersecurity-logs 2>/dev/null
echo "   Injection SQL envoyee -> 10.20.30.40 | user_agent: sqlmap"

# ── Etape 3 : Scenario Volume ────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  SCENARIO 3 : Anomalie Volumetrique (15 Mo)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

VOLUME_MSG="{\"timestamp\":\"${NOW}\",\"source_ip\":\"172.16.0.5\",\"dest_ip\":\"8.8.8.8\",\"protocol\":\"TCP\",\"action\":\"allowed\",\"threat_label\":\"suspicious\",\"log_type\":\"firewall\",\"bytes_transferred\":15728640,\"user_agent\":\"\",\"request_path\":\"/data/export\"}"
echo "${VOLUME_MSG}" | docker exec -i ${KAFKA_CONTAINER} \
    kafka-console-producer.sh \
    --bootstrap-server localhost:9092 \
    --topic cybersecurity-logs 2>/dev/null
echo "   Volume anormal envoye -> 172.16.0.5 | 15 Mo en 10 secondes"

# ── Attente des alertes ──────────────────────────────────────────────
echo ""
echo "⏳ Attente 5 secondes pour le traitement Spark Streaming..."
sleep 5

# ── Verification des alertes ─────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  VERIFICATION : Alertes dans Cassandra"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

ALERTS=$(curl -s "${API_URL}/threats/active")
COUNT=$(echo "${ALERTS}" | python3 -c "import sys,json; data=json.load(sys.stdin); print(len(data))" 2>/dev/null || echo "?")
echo "   Alertes actives trouvees : ${COUNT}"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  PROFIL IP : 10.10.10.1 (attaquant brute-force)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
curl -s "${API_URL}/threats/ip/10.10.10.1" | python3 -m json.tool 2>/dev/null || \
    curl -s "${API_URL}/threats/ip/10.10.10.1"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  PROFIL IP : 10.20.30.40 (attaquant SQLi)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
curl -s "${API_URL}/threats/ip/10.20.30.40" | python3 -m json.tool 2>/dev/null || \
    curl -s "${API_URL}/threats/ip/10.20.30.40"

echo ""
echo "============================================"
echo "  ✅ Demo terminee !"
echo "============================================"
echo ""
echo "  Prochaines etapes :"
echo "  - Dashboard : http://localhost:3000"
echo "  - API REST  : http://localhost:8080/threats/active"
echo "  - HDFS UI   : http://localhost:9870"
echo "  - HBase UI  : http://localhost:16010"
echo ""
