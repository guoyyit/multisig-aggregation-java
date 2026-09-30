package com.github.guoyyit.multisigaggregationjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.nio.file.Path;
import java.nio.file.Paths;

/** Configuration properties prefixed with {@code multisig}. */
@ConfigurationProperties(prefix = "multisig")
public class ServiceProperties {

    private Path stateFile = Paths.get("data", "multisig-state.json");
    private long defaultTimeoutMillis = 300_000L;
    private int maxInvalidAttempts = 3;
    private long sweepIntervalMillis = 5_000L;
    private boolean markIncompleteSessionsFailedOnStartup = true;

    public Path getStateFile() {
        return stateFile;
    }

    public void setStateFile(Path stateFile) {
        this.stateFile = stateFile;
    }

    public long getDefaultTimeoutMillis() {
        return defaultTimeoutMillis;
    }

    public void setDefaultTimeoutMillis(long defaultTimeoutMillis) {
        this.defaultTimeoutMillis = defaultTimeoutMillis;
    }

    public int getMaxInvalidAttempts() {
        return maxInvalidAttempts;
    }

    public void setMaxInvalidAttempts(int maxInvalidAttempts) {
        this.maxInvalidAttempts = maxInvalidAttempts;
    }

    public long getSweepIntervalMillis() {
        return sweepIntervalMillis;
    }

    public void setSweepIntervalMillis(long sweepIntervalMillis) {
        this.sweepIntervalMillis = sweepIntervalMillis;
    }

    public boolean isMarkIncompleteSessionsFailedOnStartup() {
        return markIncompleteSessionsFailedOnStartup;
    }

    public void setMarkIncompleteSessionsFailedOnStartup(boolean markIncompleteSessionsFailedOnStartup) {
        this.markIncompleteSessionsFailedOnStartup = markIncompleteSessionsFailedOnStartup;
    }
}
