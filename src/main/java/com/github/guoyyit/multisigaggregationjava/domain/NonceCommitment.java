package com.github.guoyyit.multisigaggregationjava.domain;

/**
 * A signer's public nonce commitment for one signing round.
 *
 * @param keyId  submitting signer
 * @param r1Hex  compressed encoding of R<sub>1</sub>
 * @param r2Hex  compressed encoding of R<sub>2</sub> (single-signer round uses only R<sub>1</sub>)
 */
public record NonceCommitment(String keyId, String r1Hex, String r2Hex) {
}
