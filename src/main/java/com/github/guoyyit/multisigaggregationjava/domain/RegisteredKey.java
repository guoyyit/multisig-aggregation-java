package com.github.guoyyit.multisigaggregationjava.domain;

/**
 * A registered public key together with its proof of possession metadata.
 *
 * @param keyId         stable identifier chosen at registration
 * @param publicKeyHex  compressed SEC1 encoding of the P-256 public key
 * @param status        current lifecycle status
 * @param popSigHex     proof-of-possession Schnorr signature hex
 * @param popMessageHex exact message the proof of possession signs
 * @param registeredAt  epoch millis of registration
 * @param revokedAt     epoch millis of revocation, or {@code null}
 * @param revokedReason audit reason supplied at revocation
 */
public record RegisteredKey(
        String keyId,
        String publicKeyHex,
        KeyStatus status,
        String popSigHex,
        String popMessageHex,
        long registeredAt,
        Long revokedAt,
        String revokedReason
) {
}
