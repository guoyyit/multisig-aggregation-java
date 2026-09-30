package com.github.guoyyit.multisigaggregationjava.config;

import com.github.guoyyit.multisigaggregationjava.service.KeyService;
import com.github.guoyyit.multisigaggregationjava.service.RecoveryService;
import com.github.guoyyit.multisigaggregationjava.service.SigningService;
import com.github.guoyyit.multisigaggregationjava.store.PersistentStateStore;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/** Wires the persistence store and services as Spring beans. */
@Configuration
@EnableConfigurationProperties(ServiceProperties.class)
public class AppConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    public PersistentStateStore persistentStateStore(ServiceProperties properties) {
        return new PersistentStateStore(properties.getStateFile());
    }

    @Bean
    public KeyService keyService(PersistentStateStore store, Clock clock) {
        return new KeyService(store, clock);
    }

    @Bean
    public SigningService signingService(PersistentStateStore store, KeyService keyService, Clock clock,
                                         ServiceProperties properties) {
        return new SigningService(store, keyService, clock,
                properties.getDefaultTimeoutMillis(), properties.getMaxInvalidAttempts());
    }

    @Bean
    public RecoveryService recoveryService(PersistentStateStore store, ServiceProperties properties) {
        return new RecoveryService(store, properties.isMarkIncompleteSessionsFailedOnStartup());
    }
}
