package com.github.guoyyit.multisigaggregationjava.api;

import java.util.List;

/** Request/response DTOs for the REST API. All binary values are hex strings. */
public final class ApiDtos {

    private ApiDtos() {
    }

    public record RegisterKeyRequest(String keyId, String publicKeyHex, String popSigHex,
                                     String popMessageHex) {
    }

    public record RotateKeyRequest(String oldKeyId, String newKeyId, String newPublicKeyHex,
                                   String popSigHex, String popMessageHex) {
    }

    public record RevokeKeyRequest(String reason) {
    }

    public record CreateSessionRequest(String sessionId, String messageHex, List<String> participantKeyIds,
                                       Long timeoutMillis) {
    }

    public record CommitmentRequest(String keyId, String r1Hex, String r2Hex) {
    }

    public record PartialSignatureRequest(String keyId, String scalarHex) {
    }

    public record CancelRequest(String reason) {
    }

    public record VerifyRequest(String messageHex, String aggregateKeyHex, String rHex, String sHex) {
    }

    public record ErrorResponse(String code, String message) {
    }
}
