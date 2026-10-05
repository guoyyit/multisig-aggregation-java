package com.github.guoyyit.multisigaggregationjava.web;

import com.github.guoyyit.multisigaggregationjava.service.AggregationService;
import com.github.guoyyit.multisigaggregationjava.service.SessionService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/sessions")
public class SessionController {

    public record CreateSessionRequest(String sessionId, String messageHex,
                                       List<String> participantKeyIds, String retryOf) {
    }

    public record CommitmentRequest(String keyId, String commitmentHex) {
    }

    public record NonceRequest(String keyId, String nonceHex) {
    }

    public record PartialRequest(String keyId, String partialHex) {
    }

    public record OfflineRequest(String keyId, String reason) {
    }

    private final SessionService sessions;
    private final AggregationService aggregation;

    public SessionController(SessionService sessions, AggregationService aggregation) {
        this.sessions = sessions;
        this.aggregation = aggregation;
    }

    @PostMapping
    public Map<String, Object> create(@RequestBody CreateSessionRequest request) {
        return aggregation.sessionView(sessions.create(
                request.sessionId(), request.messageHex(), request.participantKeyIds(),
                request.retryOf()));
    }

    @PostMapping("/{sessionId}/commitments")
    public Map<String, Object> commitment(@PathVariable String sessionId,
                                          @RequestBody CommitmentRequest request) {
        return aggregation.sessionView(
                sessions.submitCommitment(sessionId, request.keyId(), request.commitmentHex()));
    }

    @PostMapping("/{sessionId}/nonces")
    public Map<String, Object> nonce(@PathVariable String sessionId,
                                     @RequestBody NonceRequest request) {
        return aggregation.sessionView(
                sessions.submitNonce(sessionId, request.keyId(), request.nonceHex()));
    }

    @PostMapping("/{sessionId}/partials")
    public Map<String, Object> partial(@PathVariable String sessionId,
                                       @RequestBody PartialRequest request) {
        return aggregation.sessionView(
                sessions.submitPartial(sessionId, request.keyId(), request.partialHex()));
    }

    @PostMapping("/{sessionId}/cancel")
    public Map<String, Object> cancel(@PathVariable String sessionId,
                                      @RequestBody(required = false) Map<String, String> body) {
        String reason = body == null ? null : body.getOrDefault("reason", null);
        return aggregation.sessionView(sessions.cancel(sessionId, reason));
    }

    @PostMapping("/{sessionId}/offline")
    public Map<String, Object> offline(@PathVariable String sessionId,
                                       @RequestBody OfflineRequest request) {
        return aggregation.sessionView(sessions.markParticipantOffline(
                sessionId, request.keyId(), request.reason()));
    }

    @PostMapping("/{sessionId}/retry")
    public Map<String, Object> retry(@PathVariable String sessionId) {
        return aggregation.sessionView(sessions.retry(sessionId));
    }

    @GetMapping("/{sessionId}")
    public Map<String, Object> get(@PathVariable String sessionId) {
        return aggregation.sessionView(sessions.get(sessionId));
    }
}
