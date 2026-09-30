package com.github.guoyyit.multisigaggregationjava.domain;

/**
 * Business exception carrying a distinguishable {@link ErrorCode}.
 */
public class ServiceException extends RuntimeException {

    private final ErrorCode errorCode;

    public ServiceException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public ErrorCode errorCode() {
        return errorCode;
    }
}
