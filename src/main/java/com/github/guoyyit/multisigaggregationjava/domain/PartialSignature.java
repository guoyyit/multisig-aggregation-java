package com.github.guoyyit.multisigaggregationjava.domain;

/**
 * A signer's partial signature for one signing round.
 *
 * @param keyId     submitting signer
 * @param scalarHex hex encoded scalar s<sub>i</sub>
 */
public record PartialSignature(String keyId, String scalarHex) {
}
