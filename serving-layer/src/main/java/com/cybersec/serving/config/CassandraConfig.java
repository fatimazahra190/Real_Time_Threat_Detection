package com.cybersec.serving.config;

import com.datastax.oss.driver.api.core.CqlSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.net.InetSocketAddress;

/**
 * Configuration Spring Boot pour la session Cassandra.
 */
@Configuration
public class CassandraConfig {

    private static final Logger logger = LoggerFactory.getLogger(CassandraConfig.class);

    @Value("${cassandra.host:cassandra}")
    private String cassandraHost;

    @Value("${cassandra.port:9042}")
    private int cassandraPort;

    @Value("${cassandra.datacenter:datacenter1}")
    private String datacenter;

    @Value("${cassandra.keyspace:cybersecurity}")
    private String keyspace;

    /**
     * Cree la session CQL Cassandra.
     * Spring la ferme automatiquement a l'arret de l'application.
     */
    @Bean(destroyMethod = "close")
    public CqlSession cqlSession() {
        logger.info("Connexion Cassandra: {}:{} | keyspace: {}", cassandraHost, cassandraPort, keyspace);

        CqlSession session = CqlSession.builder()
                .addContactPoint(new InetSocketAddress(cassandraHost, cassandraPort))
                .withLocalDatacenter(datacenter)
                .withKeyspace(keyspace)
                .build();

        logger.info("✅ Connexion Cassandra etablie.");
        return session;
    }
}
