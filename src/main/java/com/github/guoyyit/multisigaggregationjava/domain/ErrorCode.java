package com.github.guoyyit.multisigaggregationjava.domain;

import org.springframework.http.HttpStatus;

/**
 * Distinguishable error codes returned by the service.
 */
public enum ErrorCode {

    KEY_NOT_FOUND(HttpStatus.NOT_FOUND),
    KEY_REVOKED(HttpStatus.CONFLICT),
    KEY_ALREADY_REGISTERED(HttpStatus.CONFLICT),
    INVALID_PUBLIC_KEY(HttpStatus.BAD_REQUEST),
    INVALID_PROOF_OF_POSSESSION(HttpStatus.BAD_REQUEST),
    INVALID_NONCE_COMMITMENT(HttpStatus.BAD_REQUEST),
    DUPLICATE_COMMITMENT(HttpStatus.CONFLICT),
    PARTIAL_SIGNATURE_REUSE(HttpStatus.CONFLICT),
    INVALID_PARTIAL_SIGNATURE(HttpStatus.BAD_REQUEST),
    SESSION_NOT_FOUND(HttpStatus.NOT_FOUND),
    SESSION_NOT_OPEN(HttpStatus.CONFLICT),
    NOT_A_PARTICIPANT(HttpStatus.FORBIDDEN),
    PARTICIPANT_REVOKED(HttpStatus.CONFLICT),
    SESSION_INCOMPLETE(HttpStatus.CONFLICT),
    SESSION_EXPIRED(HttpStatus.GONE),
    SESSION_NOT_CANCELLABLE(HttpStatus.CONFLICT),
    SESSION_NOT_RETRYABLE(HttpStatus.CONFLICT),
    SIGNATURE_VERIFICATION_FAILED(HttpStatus.BAD_REQUEST);

    private final HttpStatus httpStatus;

    ErrorCode(HttpStatus httpStatus) {
        this.httpStatus = httpStatus;
    }

    public HttpStatus httpStatus() {
        return httpStatus;
    }

    public String code() {
        return name();
    }
}
