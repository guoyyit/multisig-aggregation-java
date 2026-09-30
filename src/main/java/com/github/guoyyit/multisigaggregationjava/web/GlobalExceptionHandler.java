package com.github.guoyyit.multisigaggregationjava.web;

import com.github.guoyyit.multisigaggregationjava.core.ErrorCode;
import com.github.guoyyit.multisigaggregationjava.core.ServiceException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ServiceException.class)
    public ResponseEntity<Map<String, Object>> handleService(ServiceException ex) {
        ErrorCode code = ex.errorCode();
        return ResponseEntity.status(statusOf(code)).body(body(code, ex.getMessage()));
    }

    @ExceptionHandler({IllegalArgumentException.class, HttpMessageNotReadableException.class})
    public ResponseEntity<Map<String, Object>> handleBadRequest(Exception ex) {
        return ResponseEntity.badRequest()
                .body(body(ErrorCode.VALIDATION_ERROR, ex.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleOther(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(body(ErrorCode.INTERNAL_ERROR, ex.getMessage()));
    }

    private static HttpStatus statusOf(ErrorCode code) {
        return switch (code) {
            case KEY_NOT_FOUND, SESSION_NOT_FOUND -> HttpStatus.NOT_FOUND;
            case SESSION_EXPIRED -> HttpStatus.GONE;
            case CONCURRENT_UPDATE -> HttpStatus.CONFLICT;
            default -> HttpStatus.BAD_REQUEST;
        };
    }

    private static Map<String, Object> body(ErrorCode code, String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", code.code());
        body.put("message", message == null ? code.defaultMessage() : message);
        return body;
    }
}
