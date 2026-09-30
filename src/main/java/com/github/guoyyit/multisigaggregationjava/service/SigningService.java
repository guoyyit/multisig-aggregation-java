package com.github.guoyyit.multisigaggregationjava.service;

import com.github.guoyyit.multisigaggregationjava.crypto.CurveP256;
import com.github.guoyyit.multisigaggregationjava.crypto.EcPoint;
import com.github.guoyyit.multisigaggregationjava.crypto.Schnorr;
import com.github.guoyyit.multisigaggregationjava.domain.AggregateSignature;
import com.github.guoyyit.multisigaggregationjava.domain.ErrorCode;
import com.github.guoyyit.multisigaggregationjava.domain.FailureReason;
import com.github.guoyyit.multisigaggregationjava.domain.NonceCommitment;
import com.github.guoyyit.multisigaggregationjava.domain.PartialSignature;
import com.github.guoyyit.multisigaggregationjava.domain.RegisteredKey;
import com.github.guoyyit.multisigaggregationjava.domain.SessionStatus;
import com.github.guoyyit.multisigaggregationjava.domain.SignSession;
import com.github.guoyyit.multisigaggregationjava.domain.SigningView;
import com.github.guoyyit.multisigaggregationjava.domain.VerificationResult;
import com.github.guoyyit.multisigaggregationjava.domain.ServiceException;
import com.github.guoyyit.multisigaggregationjava.store.PersistentStateStore;

import java.math.BigInteger;
import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Signing session lifecycle: creation, two-round nonce commitment collection,
 * idempotent partial signature submission, aggregation, verification, retry,
 * cancellation and timeout handling.
 */
public class SigningService {

    private final PersistentStateStore store;
    private final KeyService keyService;
    private final Clock clock;
    private final long defaultTimeoutMillis;
    private final int maxInvalidAttempts;

    public SigningService(PersistentStateStore store, KeyService keyService,
                          long defaultTimeoutMillis, int maxInvalidAttempts) {
        this(store, keyService, Clock.systemUTC(), defaultTimeoutMillis, maxInvalidAttempts);
    }

    public SigningService(PersistentStateStore store, KeyService keyService, Clock clock,
                          long defaultTimeoutMillis, int maxInvalidAttempts) {
        this.store = store;
        this.keyService = keyService;
        this.clock = clock;
        this.defaultTimeoutMillis = defaultTimeoutMillis;
        this.maxInvalidAttempts = maxInvalidAttempts;
        this.store.load();
    }

    /** Open a session over active participants; computes the aggregate public key. */
    public SignSession createSession(String sessionId, String messageHex, List<String> participantKeyIds,
                                     Long timeoutMillis) {
        if (sessionId == null || sessionId.isBlank()) {
            throw new ServiceException(ErrorCode.SESSION_INCOMPLETE, "sessionId must not be blank");
        }
        if (messageHex == null || messageHex.isBlank()) {
            throw new ServiceException(ErrorCode.SESSION_INCOMPLETE, "messageHex must not be blank");
        }
        hex(messageHex);
        if (participantKeyIds == null || participantKeyIds.isEmpty()) {
            throw new ServiceException(ErrorCode.SESSION_INCOMPLETE, "at least one participant is required");
        }
        List<String> canonical = new ArrayList<>(participantKeyIds.stream().distinct().sorted().toList());
        if (canonical.size() != participantKeyIds.size()) {
            throw new ServiceException(ErrorCode.INVALID_PUBLIC_KEY, "duplicate participants are not allowed");
        }
        Map<String, String> publicKeysHex = new LinkedHashMap<>();
        List<EcPoint> publicKeys = new ArrayList<>();
        for (String keyId : canonical) {
            RegisteredKey key = keyService.requireActive(keyId);
            publicKeysHex.put(keyId, key.publicKeyHex());
            publicKeys.add(EcPoint.decodeCompressedHex(key.publicKeyHex()));
        }
        EcPoint aggregateKey = Schnorr.aggregatePublicKey(publicKeys);

        store.lock().writeLock().lock();
        try {
            if (store.getSession(sessionId) != null) {
                throw new ServiceException(ErrorCode.SESSION_NOT_OPEN,
                        "session already exists: " + sessionId);
            }
            for (String keyId : canonical) {
                ensureKeyStillActive(keyId);
            }
            long now = clock.millis();
            SignSession session = new SignSession();
            session.setSessionId(sessionId);
            session.setMessageHex(messageHex);
            session.setParticipantKeyIds(canonical);
            session.setPublicKeysHex(publicKeysHex);
            session.setAggregateKeyHex(aggregateKey.encodeCompressedHex());
            session.setStatus(SessionStatus.OPEN);
            session.setRound(1);
            session.setCreatedAt(now);
            session.setUpdatedAt(now);
            session.setDeadlineAt(now + (timeoutMillis == null ? defaultTimeoutMillis : timeoutMillis));
            store.putSession(session);
            return session;
        } finally {
            store.lock().writeLock().unlock();
        }
    }

    public SignSession getSession(String sessionId) {
        return requireSession(sessionId);
    }

    /**
     * Accept a nonce commitment. Rejects duplicate tuples in the same round and
     * cross-session nonce reuse with a distinguishable error.
     */
    public SignSession submitCommitment(String sessionId, NonceCommitment commitment) {
        store.lock().writeLock().lock();
        try {
            SignSession session = requireOpenSessionLocked(sessionId);
            String keyId = requireParticipant(session, commitment == null ? null : commitment.keyId());
            if (commitment.r1Hex() == null || commitment.r1Hex().isBlank()) {
                throw new ServiceException(ErrorCode.INVALID_NONCE_COMMITMENT, "r1Hex is required");
            }
            EcPoint r1 = decodePoint(commitment.r1Hex(), ErrorCode.INVALID_NONCE_COMMITMENT);
            EcPoint r2 = null;
            boolean multi = session.getParticipantKeyIds().size() > 1;
            if (multi) {
                if (commitment.r2Hex() == null || commitment.r2Hex().isBlank()) {
                    throw new ServiceException(ErrorCode.DUPLICATE_COMMITMENT,
                            "multi-signer rounds require two nonces (r1 and r2)");
                }
                r2 = decodePoint(commitment.r2Hex(), ErrorCode.INVALID_NONCE_COMMITMENT);
            }
            String tupleHex = tuple(commitment.r1Hex(), multi ? commitment.r2Hex() : "");
            ensureNotExpiredLocked(session);
            ensureKeyStillActive(keyId);
            String otherSlot = store.findNonceTupleOtherSlot(tupleHex, sessionId,
                    session.getRound(), keyId);
            if (otherSlot != null) {
                throw new ServiceException(ErrorCode.DUPLICATE_COMMITMENT,
                        "nonce commitment was already used at session/round/key " + otherSlot);
            }
            NonceCommitment existing = session.getCommitments().get(keyId);
            if (existing != null) {
                if (sameCommitment(existing, commitment)) {
                    return session;
                }
                throw new ServiceException(ErrorCode.DUPLICATE_COMMITMENT,
                        "a different commitment already exists for key " + keyId
                                + " in round " + session.getRound() + "; retry to start a fresh round");
            }
            store.putNonceTuple(sessionId, session.getRound(), keyId, tupleHex);
            session.getCommitments().put(keyId, new NonceCommitment(keyId,
                    r1.encodeCompressedHex(), r2 == null ? null : r2.encodeCompressedHex()));
            touch(session);
            store.putSession(session);
            return session;
        } finally {
            store.lock().writeLock().unlock();
        }
    }

    /** Public signing view, available once every participant has committed. */
    public SigningView signingView(String sessionId) {
        store.lock().readLock().lock();
        try {
            SignSession session = requireOpenSessionForRead(sessionId);
            return buildView(session);
        } finally {
            store.lock().readLock().unlock();
        }
    }

    /**
     * Accept and verify a partial signature. Idempotent for the same key/session.
     * Rejects reused nonces against other messages and invalid partials. When all
     * valid partials are present, produces and verifies the aggregate signature
     * before marking the session COMPLETED.
     */
    public AggregateSignature submitPartial(String sessionId, PartialSignature partial) {
        store.lock().writeLock().lock();
        try {
            SignSession session = requireOpenSessionLocked(sessionId);
            String keyId = requireParticipant(session, partial == null ? null : partial.keyId());
            BigInteger sI = decodeScalar(partial == null ? null : partial.scalarHex());
            ensureNotExpiredLocked(session);
            ensureKeyStillActive(keyId);
            SigningView view = buildView(session);
            if (session.getPartials().containsKey(keyId)) {
                if (session.getPartials().get(keyId).scalarHex().equals(partial.scalarHex())) {
                    return session.getStatus() == SessionStatus.COMPLETED
                            ? session.getAggregateSignature() : null;
                }
                return rejectPartial(session, keyId, "conflicting partial signature for an idempotent key");
            }

            NonceCommitment commitment = session.getCommitments().get(keyId);
            if (commitment == null) {
                throw new ServiceException(ErrorCode.SESSION_INCOMPLETE,
                        "signer has not submitted a nonce commitment for this round: " + keyId);
            }

            EcPoint r1 = EcPoint.decodeCompressedHex(commitment.r1Hex());
            EcPoint r2 = commitment.r2Hex() == null ? null
                    : EcPoint.decodeCompressedHex(commitment.r2Hex());
            EcPoint publicKey = EcPoint.decodeCompressedHex(session.getPublicKeysHex().get(keyId));
            int index = session.getParticipantKeyIds().indexOf(keyId);
            BigInteger coefficient = Schnorr.keyAggregationCoefficient(orderedPublicKeys(session), index);
            BigInteger b = new BigInteger(1, hex(view.bHex()));
            BigInteger e = new BigInteger(1, hex(view.eHex()));
            if (!Schnorr.verifyPartial(r1, r2, publicKey, sI, coefficient, b, e)) {
                return rejectPartial(session, keyId, "partial signature failed verification");
            }
            String reuseRef = store.markConsumedPartial(
                    tuple(commitment.r1Hex(), commitment.r2Hex()),
                    sessionId + "#" + session.getRound());
            if (reuseRef != null) {
                throw new ServiceException(ErrorCode.PARTIAL_SIGNATURE_REUSE,
                        "nonce tuple already used to sign another message at " + reuseRef);
            }

            session.getPartials().put(keyId, new PartialSignature(keyId, toHex(CurveP256.scalarBytes(sI))));
            session.setInvalidAttempts(0);
            touch(session);
            store.putSession(session);

            if (session.getPartials().size() == session.getParticipantKeyIds().size()) {
                return completeLocked(session, view);
            }
            return null;
        } finally {
            store.lock().writeLock().unlock();
        }
    }

    /** Return the completed aggregate signature; never returns a partial result. */
    public AggregateSignature aggregate(String sessionId) {
        SignSession session = requireSession(sessionId);
        if (session.getStatus() == SessionStatus.COMPLETED) {
            return session.getAggregateSignature();
        }
        throw new ServiceException(ErrorCode.SESSION_INCOMPLETE,
                "session is not complete (collected " + session.getPartials().size()
                        + " of " + session.getParticipantKeyIds().size() + " partial signatures)");
    }

    public VerificationResult verify(String sessionId) {
        SignSession session = requireSession(sessionId);
        AggregateSignature signature = session.getAggregateSignature();
        if (signature == null) {
            throw new ServiceException(ErrorCode.SESSION_INCOMPLETE, "no aggregate signature exists yet");
        }
        return verifyStandalone(signature.messageHex(), signature.aggregateKeyHex(),
                signature.rHex(), signature.sHex());
    }

    /** Verify an aggregate signature independently against its aggregate key. */
    public VerificationResult verifyStandalone(String messageHex, String aggregateKeyHex,
                                               String rHex, String sHex) {
        try {
            byte[] message = hex(messageHex);
            EcPoint aggregateKey = EcPoint.decodeCompressedHex(aggregateKeyHex);
            EcPoint r = EcPoint.decodeCompressedHex(rHex);
            BigInteger s = new BigInteger(1, hex(sHex));
            boolean valid = Schnorr.verifyAggregate(message, aggregateKey, r, s);
            return valid ? VerificationResult.ok()
                    : VerificationResult.fail("s*G != R + e*X");
        } catch (RuntimeException ex) {
            return VerificationResult.fail("malformed signature: " + ex.getMessage());
        }
    }

    /** Cancel an OPEN or FAILED session; COMPLETED sessions are not cancellable. */
    public SignSession cancel(String sessionId, String reason) {
        store.lock().writeLock().lock();
        try {
            SignSession session = requireSession(sessionId);
            if (session.getStatus() == SessionStatus.COMPLETED) {
                throw new ServiceException(ErrorCode.SESSION_NOT_CANCELLABLE,
                        "completed sessions cannot be cancelled");
            }
            if (session.getStatus() == SessionStatus.CANCELLED) {
                return session;
            }
            session.setStatus(SessionStatus.CANCELLED);
            session.setFailureReason(null);
            touch(session);
            store.putSession(session);
            return session;
        } finally {
            store.lock().writeLock().unlock();
        }
    }

    /** Start a fresh round (new nonces, deadline) for a FAILED session. */
    public SignSession retry(String sessionId) {
        store.lock().writeLock().lock();
        try {
            SignSession session = requireSession(sessionId);
            if (session.getStatus() != SessionStatus.FAILED) {
                throw new ServiceException(ErrorCode.SESSION_NOT_RETRYABLE,
                        "only FAILED sessions can be retried; current status is " + session.getStatus());
            }
            session.setStatus(SessionStatus.OPEN);
            session.setFailureReason(null);
            session.setRecoveredAfterRestart(false);
            session.setRound(session.getRound() + 1);
            session.setCommitments(new LinkedHashMap<>());
            session.setPartials(new LinkedHashMap<>());
            session.setInvalidAttempts(0);
            session.setAggregateSignature(null);
            session.setDeadlineAt(clock.millis() + defaultTimeoutMillis);
            touch(session);
            store.putSession(session);
            return session;
        } finally {
            store.lock().writeLock().unlock();
        }
    }

    /** Move timed-out OPEN sessions to FAILED(retryable). Returns affected ids. */
    public List<String> sweepTimeouts(long now) {
        List<String> expired = new ArrayList<>();
        store.lock().writeLock().lock();
        try {
            for (SignSession session : store.allSessions()) {
                if (session.getStatus() == SessionStatus.OPEN && session.getDeadlineAt() <= now) {
                    session.setStatus(SessionStatus.FAILED);
                    session.setFailureReason(FailureReason.TIMEOUT);
                    session.setUpdatedAt(now);
                    store.putSession(session);
                    expired.add(session.getSessionId());
                }
            }
            return expired;
        } finally {
            store.lock().writeLock().unlock();
        }
    }

    private SignSession requireSession(String sessionId) {
        SignSession session = store.getSession(sessionId);
        if (session == null) {
            throw new ServiceException(ErrorCode.SESSION_NOT_FOUND, "unknown session id: " + sessionId);
        }
        return session;
    }

    private SignSession requireOpenSessionLocked(String sessionId) {
        SignSession session = requireSession(sessionId);
        sweepIfExpiredLocked(session);
        requireOpen(session);
        return session;
    }

    private SignSession requireOpenSessionForRead(String sessionId) {
        SignSession session = requireSession(sessionId);
        requireOpen(session);
        return session;
    }

    private void requireOpen(SignSession session) {
        if (session.getStatus() != SessionStatus.OPEN) {
            throw new ServiceException(ErrorCode.SESSION_NOT_OPEN,
                    "session is " + session.getStatus()
                            + (session.getFailureReason() == null ? ""
                            : " (" + session.getFailureReason() + ")"));
        }
    }

    private void sweepIfExpiredLocked(SignSession session) {
        if (session.getStatus() == SessionStatus.OPEN && session.getDeadlineAt() <= clock.millis()) {
            session.setStatus(SessionStatus.FAILED);
            session.setFailureReason(FailureReason.TIMEOUT);
            session.setUpdatedAt(clock.millis());
            store.putSession(session);
        }
    }

    private void ensureNotExpiredLocked(SignSession session) {
        sweepIfExpiredLocked(session);
        if (session.getStatus() != SessionStatus.OPEN) {
            throw new ServiceException(ErrorCode.SESSION_EXPIRED,
                    "session failed: " + session.getFailureReason());
        }
    }

    private String requireParticipant(SignSession session, String keyId) {
        if (keyId == null || keyId.isBlank() || !session.getParticipantKeyIds().contains(keyId)) {
            throw new ServiceException(ErrorCode.NOT_A_PARTICIPANT,
                    "key id is not a session participant: " + keyId);
        }
        return keyId;
    }

    private void ensureKeyStillActive(String keyId) {
        RegisteredKey key = keyService.get(keyId);
        if (!com.github.guoyyit.multisigaggregationjava.domain.KeyStatus.ACTIVE.equals(key.status())) {
            throw new ServiceException(ErrorCode.PARTICIPANT_REVOKED,
                    "participant key was revoked mid-session: " + keyId);
        }
    }

    private List<EcPoint> orderedPublicKeys(SignSession session) {
        List<EcPoint> points = new ArrayList<>(session.getParticipantKeyIds().size());
        for (String keyId : session.getParticipantKeyIds()) {
            points.add(EcPoint.decodeCompressedHex(session.getPublicKeysHex().get(keyId)));
        }
        return points;
    }

    private SigningView buildView(SignSession session) {
        if (session.getCommitments().size() != session.getParticipantKeyIds().size()) {
            throw new ServiceException(ErrorCode.SESSION_INCOMPLETE,
                    "commitments collected " + session.getCommitments().size()
                            + " of " + session.getParticipantKeyIds().size());
        }
        boolean multi = session.getParticipantKeyIds().size() > 1;
        List<Schnorr.NoncePair> pairs = new ArrayList<>();
        for (String keyId : session.getParticipantKeyIds()) {
            NonceCommitment commitment = session.getCommitments().get(keyId);
            EcPoint r1 = EcPoint.decodeCompressedHex(commitment.r1Hex());
            EcPoint r2 = multi ? EcPoint.decodeCompressedHex(commitment.r2Hex()) : null;
            pairs.add(new Schnorr.NoncePair(r1, r2));
        }
        EcPoint aggregateKey = EcPoint.decodeCompressedHex(session.getAggregateKeyHex());
        byte[] message = hex(session.getMessageHex());
        Schnorr.AggregateNonce aggregateNonce = Schnorr.aggregateNonce(pairs, aggregateKey, message);
        BigInteger e = Schnorr.challenge(aggregateNonce.r(), aggregateKey, message);
        return new SigningView(session.getSessionId(), session.getRound(), session.getMessageHex(),
                List.copyOf(session.getParticipantKeyIds()),
                session.getParticipantKeyIds().stream().map(session.getPublicKeysHex()::get).toList(),
                session.getAggregateKeyHex(), aggregateNonce.r().encodeCompressedHex(),
                toHex(CurveP256.scalarBytes(aggregateNonce.b())),
                toHex(CurveP256.scalarBytes(e)));
    }

    private AggregateSignature completeLocked(SignSession session, SigningView view) {
        List<BigInteger> scalars = new ArrayList<>();
        for (String keyId : session.getParticipantKeyIds()) {
            scalars.add(new BigInteger(1, hex(session.getPartials().get(keyId).scalarHex())));
        }
        BigInteger s = Schnorr.sumPartials(scalars);
        EcPoint r = EcPoint.decodeCompressedHex(view.rHex());
        EcPoint aggregateKey = EcPoint.decodeCompressedHex(session.getAggregateKeyHex());
        byte[] message = hex(session.getMessageHex());
        if (!Schnorr.verifyAggregate(message, aggregateKey, r, s)) {
            throw new ServiceException(ErrorCode.SIGNATURE_VERIFICATION_FAILED,
                    "aggregated signature failed final verification; session not completed");
        }
        AggregateSignature signature = new AggregateSignature(session.getSessionId(),
                session.getMessageHex(), session.getAggregateKeyHex(), view.rHex(),
                toHex(CurveP256.scalarBytes(s)), List.copyOf(session.getParticipantKeyIds()),
                session.getRound());
        session.setStatus(SessionStatus.COMPLETED);
        session.setAggregateSignature(signature);
        touch(session);
        store.putSession(session);
        return signature;
    }

    private AggregateSignature rejectPartial(SignSession session, String keyId, String detail) {
        int attempts = session.getInvalidAttempts() + 1;
        session.setInvalidAttempts(attempts);
        touch(session);
        if (attempts >= maxInvalidAttempts) {
            session.setStatus(SessionStatus.FAILED);
            session.setFailureReason(FailureReason.INVALID_SUBMISSION);
            store.putSession(session);
            throw new ServiceException(ErrorCode.INVALID_PARTIAL_SIGNATURE,
                    detail + " from " + keyId + "; session failed after " + attempts
                            + " invalid attempts and can be retried or cancelled");
        }
        store.putSession(session);
        throw new ServiceException(ErrorCode.INVALID_PARTIAL_SIGNATURE,
                detail + " from " + keyId + " (invalid attempt " + attempts + "/" + maxInvalidAttempts + ")");
    }

    private void touch(SignSession session) {
        session.setUpdatedAt(clock.millis());
    }

    private static boolean sameCommitment(NonceCommitment a, NonceCommitment b) {
        return safeEq(a.r1Hex(), b.r1Hex()) && safeEq(a.r2Hex(), b.r2Hex());
    }

    private static boolean safeEq(String a, String b) {
        return a == null ? b == null : a.equalsIgnoreCase(b);
    }

    private static String tuple(String r1Hex, String r2Hex) {
        return r1Hex.toLowerCase() + "|" + (r2Hex == null ? "" : r2Hex.toLowerCase());
    }

    private static EcPoint decodePoint(String value, ErrorCode errorCode) {
        try {
            return EcPoint.decodeCompressedHex(value);
        } catch (RuntimeException ex) {
            throw new ServiceException(errorCode, "invalid point encoding: " + ex.getMessage());
        }
    }

    private static BigInteger decodeScalar(String value) {
        if (value == null || value.isBlank()) {
            throw new ServiceException(ErrorCode.INVALID_PARTIAL_SIGNATURE, "scalarHex is required");
        }
        try {
            BigInteger scalar = new BigInteger(1, hex(value));
            if (scalar.signum() < 0 || scalar.compareTo(CurveP256.N) >= 0) {
                throw new ServiceException(ErrorCode.INVALID_PARTIAL_SIGNATURE,
                        "scalar must be in [0, n-1]");
            }
            return scalar;
        } catch (IllegalArgumentException ex) {
            throw new ServiceException(ErrorCode.INVALID_PARTIAL_SIGNATURE,
                    "scalar must be 32-byte hex encoded");
        }
    }

    private static byte[] hex(String hex) {
        String s = hex.trim();
        if (s.length() % 2 != 0) {
            throw new IllegalArgumentException("odd-length hex");
        }
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int high = Character.digit(s.charAt(i * 2), 16);
            int low = Character.digit(s.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("invalid hex digit");
            }
            out[i] = (byte) ((high << 4) + low);
        }
        return out;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
