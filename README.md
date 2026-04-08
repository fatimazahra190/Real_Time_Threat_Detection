# 🛡️ CyberSec Threat Detection System

**Architecture Lambda — Detection de Menaces Big Data**

Systeme complet de detection de menaces de cybersecurite base sur l'architecture Lambda, ingérant des logs réseau pour identifier automatiquement les comportements malveillants en temps réel et historiquement.

---

## Architecture

```
CSV/Logs ──▶ HDFS ──▶ Spark Batch ──▶ HBase ──────────────┐
                                                            ▼
Logs live ──▶ Kafka ──▶ Spark Streaming ──▶ Cassandra ──▶ API REST ──▶ Dashboard
                                                            ▲
                                               Fusion batch + speed
```

| Couche | Technologie | Rôle |
|--------|-------------|------|
| Batch | HDFS + Spark | Analyses historiques (Top IPs, patterns) |
| Speed | Kafka + Spark Streaming | Détection temps réel (< 5 secondes) |
| Serving | Spring Boot REST + Dashboard HTML | Exposition et visualisation |

---

## Prérequis

- Docker 24+
- Java 11 (JDK)
- Maven 3.8+
- Python 3.9+ (producteur Kafka)
- RAM recommandée : 16 Go minimum

---

## Démarrage rapide

### 1. Lancer l'infrastructure

```bash
# Copier les variables d'environnement
cp .env.local .env

# Lancer tous les conteneurs Docker
docker compose up -d

# Initialiser HDFS, Kafka, HBase, Cassandra (attendre ~2 minutes)
chmod +x init.sh && ./init.sh
```

### 2. Charger le dataset

```bash
# Copier le CSV dans HDFS
docker cp cybersecurity_threat_detection_logs.csv hadoop-hdfs:/tmp/
docker exec hadoop-hdfs hdfs dfs -put /tmp/cybersecurity_threat_detection_logs.csv \
    /data/cybersecurity/logs/year=2023/month=10/day=15/

# Convertir CSV -> Parquet (Job Spark)
cd batch-layer && mvn clean package -DskipTests
docker exec spark-submit spark-submit \
    --class com.cybersec.batch.jobs.ConvertToParquet \
    batch-layer/target/batch-layer-1.0-SNAPSHOT.jar
```

### 3. Lancer les jobs batch

```bash
# Job 1 : Top 10 IPs malveillantes -> HBase
spark-submit --class com.cybersec.batch.jobs.TopMaliciousIPs \
    batch-layer/target/batch-layer-1.0-SNAPSHOT.jar

# Job 2 : Port scan detection -> HBase
spark-submit --class com.cybersec.batch.jobs.PortScanDetector \
    batch-layer/target/batch-layer-1.0-SNAPSHOT.jar

# Job 3 : SQLi/XSS/LFI patterns -> HBase
spark-submit --class com.cybersec.batch.jobs.AttackPatternDetector \
    batch-layer/target/batch-layer-1.0-SNAPSHOT.jar

# Job 4 : Analyse volumetrique -> HBase
spark-submit --class com.cybersec.batch.jobs.VolumeAnalysis \
    batch-layer/target/batch-layer-1.0-SNAPSHOT.jar
```

### 4. Lancer la couche Speed

```bash
# Compiler et lancer le streaming Spark
cd speed-layer && mvn clean package -DskipTests
spark-submit --class com.cybersec.speed.StreamingApp \
    speed-layer/target/speed-layer-1.0-SNAPSHOT.jar &

# Lancer le producteur Kafka (depuis un autre terminal)
cd speed-layer/producer
pip install -r requirements.txt
python kafka_producer.py --input ../../cybersecurity_threat_detection_logs.csv --loop
```

### 5. Lancer l'API REST

```bash
cd serving-layer
mvn clean package -DskipTests
mvn spring-boot:run
# ou via Docker (apres build):
# docker compose up api-rest
```

### 6. Acceder aux interfaces

| Interface | URL |
|-----------|-----|
| Dashboard | http://localhost:3000 |
| API REST | http://localhost:8080 |
| HDFS UI | http://localhost:9870 |
| HBase UI | http://localhost:16010 |

---

## API REST — Endpoints

| Méthode | Endpoint | Description | SLA |
|---------|----------|-------------|-----|
| GET | `/health` | Statut de l'API | < 50ms |
| GET | `/threats/ip/{ip}` | Profil complet d'une IP (batch+speed) | < 200ms |
| GET | `/threats/active` | Toutes les alertes actives (24h) | < 300ms |
| GET | `/threats/stats` | Statistiques globales batch | < 500ms |
| GET | `/threats/timeline` | Evolution temporelle | < 500ms |

**Exemple de réponse `/threats/ip/192.168.1.45` :**
```json
{
  "ip": "192.168.1.45",
  "batch_layer": {
    "reputationScore": 87,
    "totalHistoricalEvents": 1243,
    "attackTypesDetected": ["BRUTE_FORCE", "SQLI", "PORT_SCAN"]
  },
  "speed_layer": {
    "activeAlerts": 3,
    "currentThreatScore": 92,
    "recentAttackTypes": ["BRUTE_FORCE", "TOOL_DETECTED"]
  },
  "recommendation": "BLOCK",
  "confidence": 0.94
}
```

---

## Détections implémentées

| Type | Déclencheur | Score | Couche |
|------|-------------|-------|--------|
| Brute-Force | 5+ connexions bloquées en 1 min | 70 + 2/tentative | Speed |
| Port Scan | 20+ destinations distinctes TCP en 5 min | 60+ | Batch + Speed |
| SQLi / XSS / LFI | Pattern regex dans request_path | 85 / 75 / 70 | Batch + Speed |
| Outil malveillant | sqlmap, nikto, hydra... dans user_agent | 95 | Batch + Speed |
| Anomalie volume | > 10 Mo en 10 secondes par IP | 80+ | Speed |

---

## Demo rapide

```bash
chmod +x demo.sh && ./demo.sh
```

Lance 3 scénarios d'attaque et vérifie les alertes générées.

---

## Tests

```bash
# Tests batch layer
cd batch-layer && mvn test

# Tests speed layer
cd speed-layer && mvn test

# Tests serving layer
cd serving-layer && mvn test
```

---

## Structure du projet

```
projet-cybersec/
├── docker-compose.yml          # Infrastructure complète
├── init.sh                     # Initialisation (HDFS, Kafka, HBase, Cassandra)
├── demo.sh                     # Scénario de démo end-to-end
├── config/hadoop/              # core-site.xml, hdfs-site.xml
├── batch-layer/                # Jobs Spark (Maven)
│   └── src/main/java/com/cybersec/batch/
│       ├── jobs/               # 4 analyses Spark
│       └── utils/HBaseWriter   # Ecriture HBase
├── speed-layer/                # Spark Streaming + Kafka (Maven)
│   ├── producer/kafka_producer.py
│   └── src/main/java/com/cybersec/speed/
│       ├── detectors/          # 3 détecteurs temps réel
│       └── utils/CassandraWriter
├── serving-layer/              # API REST Spring Boot (Maven)
│   └── src/main/java/com/cybersec/serving/
│       ├── controllers/        # ThreatController, HealthController
│       ├── services/           # HBaseService, CassandraService, ThreatFusionService
│       └── models/             # ThreatProfile, ActiveAlert, IPReputation
└── dashboard/html/             # Dashboard HTML/CSS/JS (Chart.js)
```

---

## Logique de recommandation

| Score batch | Alertes actives | Recommandation |
|-------------|-----------------|----------------|
| > 80 | ≥ 1 | **BLOCK** — Blocage immédiat |
| 50 - 80 | N/A | **MONITOR** — Surveillance renforcée |
| < 50 | 0 | **ALLOW** — Autoriser avec log |
