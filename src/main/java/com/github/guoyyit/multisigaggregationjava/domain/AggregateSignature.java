package com.github.guoyyit.multisigaggregationjava.domain;

import java.util.List;

/**
 * The compact aggregate signature produced by a completed session.
 *
 * @param sessionId       originating session
 * @param messageHex      signed message
 * @param aggregateKeyHex aggregated public key (compressed)
 * @param rHex            aggregate nonce R (compressed)
 * @param sHex            aggregate scalar s
 * @param participants    key ids that contributed, in canonical order
 * @param round           signing round that completed
 */
public record AggregateSignature(
        String sessionId,
        String messageHex,
        String aggregateKeyHex,
        String rHex,
        String sHex,
        List<String> participants,
        int round
) {
}
