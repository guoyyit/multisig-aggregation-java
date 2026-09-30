package com.github.guoyyit.multisigaggregationjava.tests.support;

import com.github.guoyyit.multisigaggregationjava.crypto.EcPoint;
import com.github.guoyyit.multisigaggregationjava.crypto.LocalSigner;
import com.github.guoyyit.multisigaggregationjava.crypto.Schnorr;
import com.github.guoyyit.multisigaggregationjava.domain.AggregateSignature;
import com.github.guoyyit.multisigaggregationjava.domain.NonceCommitment;
import com.github.guoyyit.multisigaggregationjava.domain.PartialSignature;
import com.github.guoyyit.multisigaggregationjava.domain.SignSession;
import com.github.guoyyit.multisigaggregationjava.domain.SigningView;
import com.github.guoyyit.multisigaggregationjava.service.KeyService;
import com.github.guoyyit.multisigaggregationjava.service.RecoveryService;
import com.github.guoyyit.multisigaggregationjava.service.SigningService;
import com.github.guoyyit.multisigaggregationjava.store.PersistentStateStore;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Wires the real services against a temp state directory and models local
 * signers that hold secret keys outside the aggregation service.
 */
public class TestHarness {

    public final PersistentStateStore store;
    public final KeyService keyService;
    public final SigningService signingService;
    public final Map<String, LocalSigner> signers = new LinkedHashMap<>();
    private final Clock clock;

    public TestHarness(Path stateFile) {
        this(stateFile, Clock.systemUTC(), 300_000L);
    }

    public TestHarness(Path stateFile, Clock clock, long timeoutMillis) {
        this.clock = clock;
        this.store = new PersistentStateStore(stateFile);
        this.keyService = new KeyService(store, clock);
        this.signingService = new SigningService(store, keyService, clock, timeoutMillis, 3);
    }

    public RecoveryService recoveryService(boolean markFailed) {
        return new RecoveryService(store, markFailed);
    }

    public String registerSigner(String keyId) {
        return registerSigner(keyId, LocalSigner.generate());
    }

    public String registerSigner(String keyId, LocalSigner signer) {
        signers.put(keyId, signer);
        EcPoint publicKey = signer.publicKey();
        byte[] popMessage = proofMessage(keyId, publicKey.encodeCompressedHex());
        Schnorr.StandardSignature pop = signer.signStandard(popMessage);
        String popSigHex = pop.r().encodeCompressedHex()
                + to32Hex(pop.s());
        keyService.register(keyId, publicKey.encodeCompressedHex(),
                popSigHex, toHex(popMessage));
        return publicKey.encodeCompressedHex();
    }

    public SignSession createSession(String sessionId, String message, List<String> keyIds) {
        return createSession(sessionId, message, keyIds, null);
    }

    public SignSession createSession(String sessionId, String message, List<String> keyIds, Long timeout) {
        return signingService.createSession(sessionId,
                toHex(message.getBytes(StandardCharsets.UTF_8)), keyIds, timeout);
    }

    public void commitAll(String sessionId, List<String> keyIds) {
        SignSession session = signingService.getSession(sessionId);
        boolean multi = keyIds.size() > 1;
        for (String keyId : keyIds) {
            NonceCommitment commitment = signers.get(keyId)
                    .newCommitment(sessionId, session.getRound(), multi);
            signingService.submitCommitment(sessionId,
                    new NonceCommitment(keyId, commitment.r1Hex(), commitment.r2Hex()));
        }
    }

    public AggregateSignature completeSession(String sessionId, List<String> keyIds) {
        SigningView view = signingService.signingView(sessionId);
        AggregateSignature result = null;
        for (String keyId : keyIds) {
            BigInteger partial = signers.get(keyId).signPartial(view);
            result = signingService.submitPartial(sessionId,
                    new PartialSignature(keyId, to32Hex(partial)));
        }
        if (result == null) {
            throw new IllegalStateException("aggregate signature was not produced");
        }
        return result;
    }

    /** Verify every partial signature independently against public nonces. */
    public List<Boolean> verifyAllPartialsIndividually(SigningView view,
                                                       Map<String, NonceCommitment> commitments,
                                                       Map<String, BigInteger> partials) {
        SignSession session = signingService.getSession(view.sessionId());
        List<EcPoint> publicKeys = new ArrayList<>();
        for (String keyId : view.participantKeyIds()) {
            publicKeys.add(signers.get(keyId).publicKey());
        }
        BigInteger b = new BigInteger(1, fromHex(view.bHex()));
        BigInteger e = new BigInteger(1, fromHex(view.eHex()));
        List<Boolean> results = new ArrayList<>();
        for (int i = 0; i < view.participantKeyIds().size(); i++) {
            String keyId = view.participantKeyIds().get(i);
            NonceCommitment commitment = commitments.get(keyId);
            EcPoint r1 = EcPoint.decodeCompressedHex(commitment.r1Hex());
            EcPoint r2 = commitment.r2Hex() == null ? null
                    : EcPoint.decodeCompressedHex(commitment.r2Hex());
            BigInteger ai = Schnorr.keyAggregationCoefficient(publicKeys, i);
            results.add(Schnorr.verifyPartial(r1, r2, publicKeys.get(i), partials.get(keyId), ai, b, e));
        }
        return results;
    }

    public static byte[] proofMessage(String keyId, String publicKeyHex) {
        return ("pop:" + keyId + ":" + publicKeyHex).getBytes(StandardCharsets.UTF_8);
    }

    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    public static byte[] fromHex(String hex) {
        if (hex == null || hex.isEmpty()) {
            return new byte[] {0};
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    public static String to32Hex(BigInteger scalar) {
        byte[] raw = scalar.toByteArray();
        byte[] out = new byte[32];
        int length = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - length, out, 32 - length, length);
        return toHex(out);
    }

    public long now() {
        return clock.millis();
    }

    /** A mutable fixed clock that tests can advance to trigger timeout sweeps. */
    public static final class MutableClock extends Clock {
        private long millis;

        public MutableClock() {
            this(Instant.parse("2026-01-01T00:00:00Z").toEpochMilli());
        }

        public MutableClock(long millis) {
            this.millis = millis;
        }

        public void advance(long deltaMillis) {
            this.millis += deltaMillis;
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return Instant.ofEpochMilli(millis);
        }
    }
}
