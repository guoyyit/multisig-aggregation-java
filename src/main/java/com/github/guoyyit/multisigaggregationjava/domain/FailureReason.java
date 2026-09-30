package com.github.guoyyit.multisigaggregationjava.domain;

/** Reason a session entered the FAILED state. */
public enum FailureReason {
    TIMEOUT,
    INVALID_SUBMISSION,
    RESTART_RECOVERY
}
