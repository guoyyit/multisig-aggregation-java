package com.github.guoyyit.multisigaggregationjava.model;

public enum SessionState {
    COLLECTING_COMMITMENTS,
    COMMITMENTS_FINALIZED,
    COLLECTING_SIGNATURES,
    COMPLETED,
    FAILED_RETRYABLE,
    FAILED_CANCELLED,
    EXPIRED
}
