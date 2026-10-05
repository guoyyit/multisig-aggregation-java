package com.github.guoyyit.multisigaggregationjava.model;

public record PublicKeyRecord(
        String keyId,
        String owner,
        String pubHex,
        String popHex,
        ProofStatus proofStatus,
        KeyStatus status,
        int version,
        long registeredAt,
        long revokedAt,
        String replacedById
) {
    public PublicKeyRecord {
        if (proofStatus == null) {
            if (popHex != null && !popHex.isBlank()) {
                proofStatus = ProofStatus.PRESENT;
            } else if (popHex == null && pubHex == null && status == KeyStatus.REVOKED) {
                proofStatus = ProofStatus.NOT_APPLICABLE;
            } else {
                proofStatus = ProofStatus.LEGACY_MISSING;
            }
        }
    }

    public static PublicKeyRecord empty() {
        return new PublicKeyRecord(null, null, null, null, null, null, 0, 0L, 0L, null);
    }
}
