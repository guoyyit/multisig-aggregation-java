package com.github.guoyyit.multisigaggregationjava.model;

public record PublicKeyRecord(
        String keyId,
        String owner,
        String pubHex,
        KeyStatus status,
        int version,
        long registeredAt,
        long revokedAt,
        String replacedById
) {
    public static PublicKeyRecord empty() {
        return new PublicKeyRecord(null, null, null, null, 0, 0L, 0L, null);
    }
}
