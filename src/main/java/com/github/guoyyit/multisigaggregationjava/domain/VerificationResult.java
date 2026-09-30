package com.github.guoyyit.multisigaggregationjava.domain;

/**
 * Result of verifying an aggregate signature against the aggregate public key.
 */
public record VerificationResult(boolean valid, String reason) {

    public static VerificationResult ok() {
        return new VerificationResult(true, "VALID");
    }

    public static VerificationResult fail(String reason) {
        return new VerificationResult(false, reason);
    }
}
