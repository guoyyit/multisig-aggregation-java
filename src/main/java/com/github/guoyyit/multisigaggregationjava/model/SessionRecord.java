package com.github.guoyyit.multisigaggregationjava.model;

import java.util.List;
import java.util.Map;

public record SessionRecord(
        String sessionId,
        String messageHex,
        List<String> participantKeyIds,
        String aggregatePubHex,
        SessionState state,
        FailureReason failureReason,
        long createdAt,
        long deadlineMillis,
        long finalizedAt,
        String saltHex,
        Map<String, String> commitments,
        Map<String, String> nonces,
        Map<String, String> partialSignatures,
        String aggregateSignatureHex,
        String retryOf,
        int attempt
) {
    public static SessionRecord empty() {
        return new SessionRecord(null, null, List.of(), null, null,
                FailureReason.NONE, 0L, 0L, 0L, null,
                Map.of(), Map.of(), Map.of(), null, null, 0);
    }
}
