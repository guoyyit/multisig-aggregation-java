package com.github.guoyyit.multisigaggregationjava.api;

import com.github.guoyyit.multisigaggregationjava.domain.ServiceException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Translates {@link ServiceException} into stable error responses. */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ServiceException.class)
    public ResponseEntity<ApiDtos.ErrorResponse> handle(ServiceException ex) {
        return ResponseEntity.status(ex.errorCode().httpStatus())
                .body(new ApiDtos.ErrorResponse(ex.errorCode().code(), ex.getMessage()));
    }
}
