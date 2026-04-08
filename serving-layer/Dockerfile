# ── Build stage ─────────────────────────────────────────────────────
# On part d'une image Java legere (Alpine = ~85 Mo vs ~500 Mo pour le JDK complet)
FROM eclipse-temurin:11-jre-alpine

# Metadonnees
LABEL maintainer="CyberSec Team"
LABEL version="1.0"
LABEL description="API REST Serving Layer - CyberSec Threat Detection"

# Repertoire de travail dans le conteneur
WORKDIR /app

# Copier le JAR compile par Maven (spring-boot:repackage cree un fat JAR)
# Le fichier doit exister : mvn clean package -DskipTests dans serving-layer/
COPY target/serving-layer-1.0-SNAPSHOT.jar app.jar

# Variables d'environnement avec valeurs par defaut.
# Surchargees dans docker-compose.yml si necessaire.
ENV HBASE_HOST=hbase
ENV ZOOKEEPER_HOST=zookeeper
ENV CASSANDRA_HOST=cassandra
ENV CASSANDRA_PORT=9042
ENV CASSANDRA_DC=datacenter1
ENV SERVER_PORT=8080

# Port expose (documentation)
EXPOSE 8080

# Healthcheck Docker : verifie que l'API repond
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD wget -q -O- http://localhost:8080/health | grep -q '"status"' || exit 1

# Commande de demarrage.
# Options JVM :
#   -Xmx512m  : limite la memoire pour ne pas ecraser les autres conteneurs
#   -Djava.security.egd : evite les blocages dus au generateur de nombres aleatoires
#   -Dspring.profiles.active=docker : active le profil Spring "docker" si defini
ENTRYPOINT ["java", \
  "-Xmx512m", \
  "-Xms128m", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-Dspring.profiles.active=docker", \
  "-jar", "app.jar"]
