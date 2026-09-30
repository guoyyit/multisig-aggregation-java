package com.github.guoyyit.multisigaggregationjava.service;

import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.time.Clock;

/** Runs crash recovery once the application is ready. */
@Component
public class StartupRecovery {

    private final RecoveryService recoveryService;
    private final Clock clock;

    public StartupRecovery(RecoveryService recoveryService, Clock clock) {
        this.recoveryService = recoveryService;
        this.clock = clock;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onReady() {
        recoveryService.recoverOnStartup(clock.millis());
    }
}
