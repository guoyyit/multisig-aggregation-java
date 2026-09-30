package com.github.guoyyit.multisigaggregationjava.model;

public enum FailureReason {
    NONE,
    TIMEOUT,
    OFFLINE,
    INVALID_COMMITMENT,
    INVALID_NONCE,
    NONCE_REUSE,
    INVALID_PARTIAL_SIGNATURE,
    CANCELLED,
    RECOVERY_ABORTED
}
