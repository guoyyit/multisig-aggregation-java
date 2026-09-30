package com.github.guoyyit.multisigaggregationjava.domain;

/**
 * Lifecycle status of a signing session.
 * <p>
 * OPEN: accepting commitments/partial signatures.
 * COMPLETED: aggregate signature produced and persisted.
 * CANCELLED: explicitly cancelled, no signature produced.
 * FAILED: timed out, invalid submissions exhausted, or interrupted by restart;
 *         a FAILED session may be retried (starting a fresh round) or cancelled.
 */
public enum SessionStatus {
    OPEN,
    COMPLETED,
    CANCELLED,
    FAILED
}
