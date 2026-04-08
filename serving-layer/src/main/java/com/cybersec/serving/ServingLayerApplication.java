package com.cybersec.serving;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Point d'entree de la Serving Layer.
 * API REST qui fusionne les donnees HBase (batch) et Cassandra (speed)
 * pour exposer un profil complet de menace par IP.
 */
@SpringBootApplication
public class ServingLayerApplication {
    public static void main(String[] args) {
        SpringApplication.run(ServingLayerApplication.class, args);
    }
}
