package com.github.guoyyit.multisigaggregationjava.domain;

import java.util.List;

/**
 * Public signing context handed to a local signer once all commitments of a round
 * have been collected. A signer uses it together with its own private key and
 * secret nonces to produce its partial signature.
 *
 * @param sessionId    session identifier
 * @param round        signing round
 * @param messageHex   message being signed
 * @param participantKeyIds canonical participant order
 * @param publicKeysHex participants' public keys in canonical order
 * @param aggregateKeyHex aggregated public key
 * @param rHex         aggregate nonce R
 * @param bHex         challenge coefficient b (zero in single-signer rounds)
 * @param eHex         Fiat-Shamir challenge e
 */
public record SigningView(
        String sessionId,
        int round,
        String messageHex,
        List<String> participantKeyIds,
        List<String> publicKeysHex,
        String aggregateKeyHex,
        String rHex,
        String bHex,
        String eHex
) {
}
