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
    /** 重启恢复：未完成会话在崩溃前已越过截止时间，恢复原因归类为超时。 */
    RECOVERY_TIMEOUT,
    /** 重启恢复：未完成会话尚未越过截止时间即被崩溃中断。 */
    RECOVERY_INTERRUPTED,
    ;
}
