package com.github.guoyyit.multisigaggregationjava.api;

import com.github.guoyyit.multisigaggregationjava.domain.AggregateSignature;
import com.github.guoyyit.multisigaggregationjava.domain.NonceCommitment;
import com.github.guoyyit.multisigaggregationjava.domain.PartialSignature;
import com.github.guoyyit.multisigaggregationjava.domain.SignSession;
import com.github.guoyyit.multisigaggregationjava.domain.SigningView;
import com.github.guoyyit.multisigaggregationjava.domain.VerificationResult;
import com.github.guoyyit.multisigaggregationjava.service.SigningService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Signing session lifecycle endpoints. */
@RestController
@RequestMapping("/api/sessions")
public class SessionController {

    private final SigningService signingService;

    public SessionController(SigningService signingService) {
        this.signingService = signingService;
    }

    @PostMapping
    public SignSession create(@RequestBody ApiDtos.CreateSessionRequest request) {
        return signingService.createSession(request.sessionId(), request.messageHex(),
                request.participantKeyIds(), request.timeoutMillis());
    }

    @GetMapping("/{sessionId}")
    public SignSession get(@PathVariable String sessionId) {
        return signingService.getSession(sessionId);
    }

    @PostMapping("/{sessionId}/commitments")
    public SignSession commitment(@PathVariable String sessionId,
                                  @RequestBody ApiDtos.CommitmentRequest request) {
        return signingService.submitCommitment(sessionId,
                new NonceCommitment(request.keyId(), request.r1Hex(), request.r2Hex()));
    }

    @GetMapping("/{sessionId}/view")
    public SigningView view(@PathVariable String sessionId) {
        return signingService.signingView(sessionId);
    }

    @PostMapping("/{sessionId}/partials")
    public AggregateSignature partial(@PathVariable String sessionId,
                                      @RequestBody ApiDtos.PartialSignatureRequest request) {
        return signingService.submitPartial(sessionId,
                new PartialSignature(request.keyId(), request.scalarHex()));
    }

    @PostMapping("/{sessionId}/aggregate")
    public AggregateSignature aggregate(@PathVariable String sessionId) {
        return signingService.aggregate(sessionId);
    }

    @GetMapping("/{sessionId}/verify")
    public VerificationResult verify(@PathVariable String sessionId) {
        return signingService.verify(sessionId);
    }

    @PostMapping("/verify")
    public VerificationResult verifyStandalone(@RequestBody ApiDtos.VerifyRequest request) {
        return signingService.verifyStandalone(request.messageHex(), request.aggregateKeyHex(),
                request.rHex(), request.sHex());
    }

    @PostMapping("/{sessionId}/cancel")
    public SignSession cancel(@PathVariable String sessionId, @RequestBody ApiDtos.CancelRequest request) {
        return signingService.cancel(sessionId, request.reason());
    }

    @PostMapping("/{sessionId}/retry")
    public SignSession retry(@PathVariable String sessionId) {
        return signingService.retry(sessionId);
    }
}
