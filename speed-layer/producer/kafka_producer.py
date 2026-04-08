#!/usr/bin/env python3
"""
Producteur Kafka — Simulation de logs de cybersecurite en temps reel.

Lit le dataset CSV ligne par ligne et publie chaque log dans le topic
Kafka 'cybersecurity-logs' a raison de 10 messages/seconde (simulant
un flux en direct depuis des firewalls, IDS et applications web).

La cle de partition est log_type pour garantir l'ordre par source :
  - Partition 0 : firewall
  - Partition 1 : ids
  - Partition 2 : application

Usage:
    pip install -r requirements.txt
    python kafka_producer.py --input /path/to/cybersecurity_threat_detection_logs.csv
    python kafka_producer.py --input data.csv --rate 50 --loop
"""

import argparse
import csv
import json
import os
import sys
import time
import signal
from datetime import datetime, timezone

from kafka import KafkaProducer
from kafka.errors import KafkaError, NoBrokersAvailable

# ── Configuration ────────────────────────────────────────────────────
KAFKA_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
TOPIC_NAME    = "cybersecurity-logs"
DEFAULT_RATE  = 10    # messages par seconde
DEFAULT_INPUT = "cybersecurity_threat_detection_logs.csv"

# Mapping log_type -> partition pour garantir l'ordre par source
PARTITION_MAP = {
    "firewall":    0,
    "ids":         1,
    "application": 2,
}

# Flag pour arret propre avec Ctrl+C
running = True

def signal_handler(sig, frame):
    global running
    print("\n⛔ Arret demande. Fermeture propre du producteur...")
    running = False

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def create_producer(servers: str) -> KafkaProducer:
    """Cree et configure le producteur Kafka."""
    print(f"🔌 Connexion a Kafka: {servers}")
    max_retries = 10
    for attempt in range(max_retries):
        try:
            producer = KafkaProducer(
                bootstrap_servers=servers,
                value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
                key_serializer=lambda k: k.encode("utf-8") if k else None,
                # Fiabilite : attendre acknowledgment de tous les replicas
                acks="all",
                retries=3,
                # Compression pour reduire le reseau
                compression_type="gzip",
                # Batch pour performances (envoie par lots de 16 Ko)
                batch_size=16384,
                linger_ms=50,
            )
            print("✅ Connecte a Kafka.")
            return producer
        except NoBrokersAvailable:
            wait = (attempt + 1) * 3
            print(f"   Kafka non disponible. Tentative {attempt+1}/{max_retries} dans {wait}s...")
            time.sleep(wait)

    print("❌ Impossible de se connecter a Kafka apres plusieurs tentatives.")
    sys.exit(1)


def normalize_row(row: dict) -> dict:
    """Normalise une ligne CSV en message JSON propre."""
    # Convertir le timestamp si present
    ts = row.get("timestamp", "")
    if ts:
        # Essayer plusieurs formats de timestamp
        for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"]:
            try:
                dt = datetime.strptime(ts, fmt)
                ts = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                break
            except ValueError:
                continue

    # Convertir bytes_transferred en entier
    bytes_val = row.get("bytes_transferred", "0")
    try:
        bytes_int = int(bytes_val) if bytes_val else 0
    except (ValueError, TypeError):
        bytes_int = 0

    return {
        "timestamp":         ts or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_ip":         row.get("source_ip", "0.0.0.0"),
        "dest_ip":           row.get("dest_ip", "0.0.0.0"),
        "protocol":          row.get("protocol", "HTTP"),
        "action":            row.get("action", "allowed"),
        "threat_label":      row.get("threat_label", "benign"),
        "log_type":          row.get("log_type", "firewall"),
        "bytes_transferred": bytes_int,
        "user_agent":        row.get("user_agent", ""),
        "request_path":      row.get("request_path", "/"),
    }


def on_send_success(record_metadata):
    """Callback en cas de succes d'envoi."""
    pass  # Silencieux pour eviter de polluer les logs


def on_send_error(excp):
    """Callback en cas d'echec d'envoi."""
    print(f"❌ Erreur envoi Kafka: {excp}")


def produce(input_file: str, rate: int, loop: bool = False):
    """
    Lit le CSV et publie les messages dans Kafka.

    Args:
        input_file: Chemin vers le fichier CSV du dataset
        rate:       Nombre de messages par seconde (10 = 1 msg/100ms)
        loop:       Si True, recommence depuis le debut quand le fichier est epuise
    """
    producer = create_producer(KAFKA_SERVERS)
    interval = 1.0 / rate  # Secondes entre chaque message

    total_sent   = 0
    total_errors = 0
    start_time   = time.time()

    print(f"📂 Lecture du fichier: {input_file}")
    print(f"📡 Topic: {TOPIC_NAME} | Rate: {rate} msg/s | Loop: {loop}")
    print(f"   Appuyer sur Ctrl+C pour arreter proprement.\n")

    pass_number = 0
    while running:
        pass_number += 1
        if pass_number > 1:
            print(f"\n🔁 Recommencement (passe {pass_number})...")

        try:
            with open(input_file, newline="", encoding="utf-8") as csvfile:
                reader = csv.DictReader(csvfile)

                for row in reader:
                    if not running:
                        break

                    message  = normalize_row(row)
                    log_type = message.get("log_type", "firewall")
                    partition = PARTITION_MAP.get(log_type, 0)

                    future = producer.send(
                        TOPIC_NAME,
                        key=log_type,
                        value=message,
                        partition=partition
                    )
                    future.add_callback(on_send_success)
                    future.add_errback(on_send_error)

                    total_sent += 1

                    # Affichage de progression toutes les 1000 messages
                    if total_sent % 1000 == 0:
                        elapsed = time.time() - start_time
                        actual_rate = total_sent / elapsed if elapsed > 0 else 0
                        print(f"   📊 Envoyes: {total_sent:,} | Rate reel: {actual_rate:.1f} msg/s | "
                              f"Erreurs: {total_errors}")

                    time.sleep(interval)

        except FileNotFoundError:
            print(f"❌ Fichier introuvable: {input_file}")
            print("   Verifier le chemin et relancer.")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Erreur lors de la lecture: {e}")
            total_errors += 1

        if not loop:
            break

    # Flush et fermeture propre
    print(f"\n⏳ Flush des messages en attente...")
    producer.flush(timeout=30)
    producer.close()

    elapsed = time.time() - start_time
    print(f"\n✅ Producteur arrete.")
    print(f"   Total envoye   : {total_sent:,} messages")
    print(f"   Total erreurs  : {total_errors}")
    print(f"   Duree totale   : {elapsed:.1f} secondes")
    print(f"   Rate moyen     : {total_sent/elapsed:.1f} msg/s" if elapsed > 0 else "")


def send_test_attack_scenario(producer_servers: str = None):
    """
    Envoie un scenario d'attaque pre-defini pour tester les detecteurs.
    Utile pour la demo ou les tests d'integration.

    Scenarios envoyes :
    1. Brute-force : 8 connexions bloquees en 30 secondes depuis 10.10.10.1
    2. Outil malveillant : sqlmap detecte dans user_agent
    3. Volume anormal : 15 Mo envoyes en 5 secondes
    """
    servers = producer_servers or KAFKA_SERVERS
    producer = create_producer(servers)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    print("\n🎯 Envoi du scenario de demo (brute-force + sqlmap + volume)...")

    # Scenario 1 : Brute-Force (8 connexions bloquees en 30s)
    for i in range(8):
        msg = {
            "timestamp": now, "source_ip": "10.10.10.1",
            "dest_ip": "192.168.0.10", "protocol": "HTTP",
            "action": "blocked", "threat_label": "malicious",
            "log_type": "firewall", "bytes_transferred": 512,
            "user_agent": "hydra/9.4", "request_path": "/admin/login"
        }
        producer.send(TOPIC_NAME, key="firewall", value=msg, partition=0)
        print(f"   Brute-force {i+1}/8 -> 10.10.10.1")
        time.sleep(0.5)

    # Scenario 2 : Outil malveillant (sqlmap)
    sqli_msg = {
        "timestamp": now, "source_ip": "10.20.30.40",
        "dest_ip": "192.168.0.20", "protocol": "HTTP",
        "action": "blocked", "threat_label": "malicious",
        "log_type": "ids", "bytes_transferred": 2048,
        "user_agent": "sqlmap/1.7.8#stable",
        "request_path": "/product.php?id=1' OR '1'='1"
    }
    producer.send(TOPIC_NAME, key="ids", value=sqli_msg, partition=1)
    print("   SQLi via sqlmap -> 10.20.30.40")

    # Scenario 3 : Anomalie volumetrique (15 Mo)
    volume_msg = {
        "timestamp": now, "source_ip": "172.16.0.5",
        "dest_ip": "8.8.8.8", "protocol": "TCP",
        "action": "allowed", "threat_label": "suspicious",
        "log_type": "firewall", "bytes_transferred": 15728640,  # 15 Mo
        "user_agent": "", "request_path": "/data/export"
    }
    producer.send(TOPIC_NAME, key="firewall", value=volume_msg, partition=0)
    print("   Volume anormal 15Mo -> 172.16.0.5")

    producer.flush(timeout=10)
    producer.close()
    print("\n✅ Scenario de demo envoye. Verifier le dashboard dans 5 secondes.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Producteur Kafka - Logs de cybersecurite"
    )
    parser.add_argument(
        "--input", default=DEFAULT_INPUT,
        help=f"Chemin vers le CSV du dataset (defaut: {DEFAULT_INPUT})"
    )
    parser.add_argument(
        "--rate", type=int, default=DEFAULT_RATE,
        help=f"Messages par seconde (defaut: {DEFAULT_RATE})"
    )
    parser.add_argument(
        "--loop", action="store_true",
        help="Recommencer depuis le debut quand le fichier est epuise"
    )
    parser.add_argument(
        "--demo", action="store_true",
        help="Envoyer uniquement un scenario de demo pre-defini et quitter"
    )

    args = parser.parse_args()

    if args.demo:
        send_test_attack_scenario()
    else:
        produce(args.input, args.rate, args.loop)
