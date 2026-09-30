package com.github.guoyyit.multisigaggregationjava.web;

import com.github.guoyyit.multisigaggregationjava.core.Hex;
import com.github.guoyyit.multisigaggregationjava.service.AggregationService;
import com.github.guoyyit.multisigaggregationjava.service.SessionService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/aggregate")
public class AggregateController {

    public record AggregateKeyRequest(List<String> keyIds) {
    }

    public record VerifyRequest(String messageHex, String aggregatePubHex, String signatureHex) {
    }

    private final AggregationService aggregation;
    private final SessionService sessions;

    public AggregateController(AggregationService aggregation, SessionService sessions) {
        this.aggregation = aggregation;
        this.sessions = sessions;
    }

    @PostMapping("/key")
    public Map<String, Object> aggregateKey(@RequestBody AggregateKeyRequest request) {
        String aggregatePubHex = aggregation.aggregatePublicHex(request.keyIds());
        return Map.of("keyIds", request.keyIds(), "aggregatePubHex", aggregatePubHex);
    }

    /**
     * 显式聚合：仅当会话已收齐全部部分签名时返回完整签名，
     * 否则返回 SESSION_INCOMPLETE / SESSION_NOT_READY，绝不泄露半成品。
     */
    @PostMapping("/{sessionId}/finalize")
    public Map<String, Object> finalizeSession(@PathVariable String sessionId) {
        byte[] signature = aggregation.aggregatePartials(sessionId);
        Map<String, Object> view = new LinkedHashMap<>(aggregation.sessionView(sessions.get(sessionId)));
        view.put("aggregateSignatureHex", Hex.encode(signature));
        return view;
    }

    @PostMapping("/verify")
    public Map<String, Object> verify(@RequestBody VerifyRequest request) {
        boolean valid = aggregation.verifyAggregate(
                request.messageHex(), request.aggregatePubHex(), request.signatureHex());
        return Map.of("valid", valid);
    }

    @GetMapping("/{sessionId}/partials-check")
    public Map<String, Object> partialsCheck(@PathVariable String sessionId) {
        boolean individuallyValid = aggregation.verifyPartialsIndividually(sessionId);
        return Map.of("sessionId", sessionId, "partialsValid", individuallyValid);
    }
}
