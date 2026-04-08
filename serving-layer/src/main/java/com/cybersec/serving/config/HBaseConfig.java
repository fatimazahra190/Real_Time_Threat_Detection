package com.cybersec.serving.config;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HBaseConfiguration;
import org.apache.hadoop.hbase.client.Connection;
import org.apache.hadoop.hbase.client.ConnectionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;

import java.io.IOException;

/**
 * Configuration Spring Boot pour la connexion HBase.
 * La connexion est partagee (singleton) entre tous les services.
 */
@org.springframework.context.annotation.Configuration
public class HBaseConfig {

    private static final Logger logger = LoggerFactory.getLogger(HBaseConfig.class);

    @Value("${hbase.zookeeper.host:zookeeper}")
    private String zookeeperHost;

    @Value("${hbase.zookeeper.port:2181}")
    private String zookeeperPort;

    @Value("${hbase.host:hbase}")
    private String hbaseHost;

    /**
     * Cree la connexion HBase partagee.
     * Spring gere le cycle de vie : la connexion est fermee a l'arret de l'app.
     */
    @Bean(destroyMethod = "close")
    public Connection hbaseConnection() throws IOException {
        logger.info("Connexion HBase: ZooKeeper={}:{}", zookeeperHost, zookeeperPort);

        Configuration config = HBaseConfiguration.create();
        config.set("hbase.zookeeper.quorum", zookeeperHost);
        config.set("hbase.zookeeper.property.clientPort", zookeeperPort);
        config.set("hbase.master", hbaseHost + ":16000");
        config.setInt("hbase.client.operation.timeout", 5000);
        config.setInt("hbase.rpc.timeout", 3000);

        Connection connection = ConnectionFactory.createConnection(config);
        logger.info("✅ Connexion HBase etablie.");
        return connection;
    }
}
