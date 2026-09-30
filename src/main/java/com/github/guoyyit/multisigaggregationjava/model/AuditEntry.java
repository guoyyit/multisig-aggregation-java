package com.github.guoyyit.multisigaggregationjava.model;

public record AuditEntry(
        String auditId,
        long timestamp,
        String action,
        String keyId,
        String sessionId,
        String detail
) {
}
