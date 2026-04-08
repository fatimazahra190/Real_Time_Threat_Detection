#!/bin/bash
# init.sh — A lancer apres "docker compose up -d"
# Initialise HDFS, Kafka, HBase et Cassandra

set -e

echo "============================================"
echo "  Init - Systeme Detection Menaces CyberSec"
echo "============================================"

# ── HADOOP ──────────────────────────────────────
echo ""
echo "⏳ Attente que Hadoop soit pret..."
MAX_RETRY=30
RETRY=0
until docker exec hadoop-hdfs hdfs dfsadmin -safemode get 2>/dev/null | grep -q "OFF"; do
  RETRY=$((RETRY+1))
  if [ $RETRY -ge $MAX_RETRY ]; then
    echo "❌ Hadoop n'a pas demarré dans le temps imparti"
    exit 1
  fi
  echo "   ... tentative $RETRY/$MAX_RETRY (attente 10s)"
  sleep 10
done

echo "✅ Hadoop pret. Creation de la structure HDFS..."
docker exec hadoop-hdfs hdfs dfs -mkdir -p /data/cybersecurity/logs/year=2023/month=10/day=15
docker exec hadoop-hdfs hdfs dfs -mkdir -p /data/cybersecurity/logs/year=2023/month=10/day=16
docker exec hadoop-hdfs hdfs dfs -mkdir -p /data/cybersecurity/logs/year=2023/month=10/day=17
docker exec hadoop-hdfs hdfs dfs -mkdir -p /data/cybersecurity/batch/ip_reputation
docker exec hadoop-hdfs hdfs dfs -mkdir -p /data/cybersecurity/batch/port_scans
docker exec hadoop-hdfs hdfs dfs -mkdir -p /data/cybersecurity/batch/attack_patterns
docker exec hadoop-hdfs hdfs dfs -mkdir -p /data/cybersecurity/batch/volume_analysis
docker exec hadoop-hdfs hdfs dfs -chmod -R 777 /data/cybersecurity
echo "   Structure HDFS creee avec succes."

# ── KAFKA ───────────────────────────────────────
echo ""
echo "⏳ Attente que Kafka soit pret..."
RETRY=0
until docker exec kafka kafka-topics.sh --bootstrap-server localhost:9092 --list 2>/dev/null; do
  RETRY=$((RETRY+1))
  if [ $RETRY -ge 20 ]; then
    echo "❌ Kafka n'a pas demarré dans le temps imparti"
    exit 1
  fi
  echo "   ... tentative $RETRY/20 (attente 5s)"
  sleep 5
done

echo "✅ Kafka pret. Creation du topic cybersecurity-logs..."
docker exec kafka kafka-topics.sh --create \
  --bootstrap-server localhost:9092 \
  --topic cybersecurity-logs \
  --partitions 3 \
  --replication-factor 1 \
  --config retention.ms=86400000 \
  --if-not-exists

echo "   Verification du topic :"
docker exec kafka kafka-topics.sh --describe \
  --topic cybersecurity-logs \
  --bootstrap-server localhost:9092

# ── CASSANDRA ───────────────────────────────────
echo ""
echo "⏳ Attente que Cassandra soit pret..."
RETRY=0
until docker exec cassandra cqlsh -e "describe keyspaces" 2>/dev/null; do
  RETRY=$((RETRY+1))
  if [ $RETRY -ge 30 ]; then
    echo "❌ Cassandra n'a pas demarré dans le temps imparti"
    exit 1
  fi
  echo "   ... tentative $RETRY/30 (attente 5s)"
  sleep 5
done

echo "✅ Cassandra pret. Creation du keyspace et de la table..."
docker exec cassandra cqlsh -e "
CREATE KEYSPACE IF NOT EXISTS cybersecurity
  WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1};

CREATE TABLE IF NOT EXISTS cybersecurity.active_threats (
  ip_source      TEXT,
  bucket_time    TIMESTAMP,
  alert_id       UUID,
  last_seen      TIMESTAMP,
  threat_score   INT,
  attack_types   SET<TEXT>,
  alert_type     TEXT,
  severity       TEXT,
  event_count    INT,
  bytes_total    BIGINT,
  user_agents    SET<TEXT>,
  log_sources    SET<TEXT>,
  PRIMARY KEY ((ip_source), bucket_time, alert_id)
) WITH default_time_to_live = 86400
  AND CLUSTERING ORDER BY (bucket_time DESC);
"
echo "   Keyspace et table Cassandra crees."

# ── HBASE ───────────────────────────────────────
echo ""
echo "⏳ Creation des tables HBase..."
sleep 10
docker exec hbase hbase shell <<'EOF'
create 'ip_reputation', {NAME => 'stats'}, {NAME => 'meta'}
create 'attack_patterns', {NAME => 'pattern'}, {NAME => 'freq'}
create 'threat_timeline', {NAME => 'counts'}, {NAME => 'breakdown'}
list
exit
EOF

echo ""
echo "============================================"
echo "  🎉 Initialisation terminee avec succes !"
echo "============================================"
echo ""
echo "  Interfaces disponibles :"
echo "  - HDFS UI     : http://localhost:9870"
echo "  - HBase UI    : http://localhost:16010"
echo "  - API REST    : http://localhost:8080/health"
echo "  - Dashboard   : http://localhost:3000"
echo ""
