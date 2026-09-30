package com.github.guoyyit.multisigaggregationjava.service;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Clock;

/** Periodically expires timed-out open sessions. */
@Component
public class TimeoutScheduler {

    private final SigningService signingService;
    private final Clock clock;

    public TimeoutScheduler(SigningService signingService, Clock clock) {
        this.signingService = signingService;
        this.clock = clock;
    }

    @Scheduled(fixedDelayString = "${multisig.sweep-interval-millis:5000}")
    public void sweep() {
        signingService.sweepTimeouts(clock.millis());
    }
}
