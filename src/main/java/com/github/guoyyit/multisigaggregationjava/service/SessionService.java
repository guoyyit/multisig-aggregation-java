package com.github.guoyyit.multisigaggregationjava.service;

import com.github.guoyyit.multisigaggregationjava.config.ServiceProperties;
import com.github.guoyyit.multisigaggregationjava.core.ErrorCode;
import com.github.guoyyit.multisigaggregationjava.core.Hex;
import com.github.guoyyit.multisigaggregationjava.core.Musig;
import com.github.guoyyit.multisigaggregationjava.core.Schnorr;
import com.github.guoyyit.multisigaggregationjava.core.ServiceException;
import com.github.guoyyit.multisigaggregationjava.model.FailureReason;
import com.github.guoyyit.multisigaggregationjava.model.PublicKeyRecord;
import com.github.guoyyit.multisigaggregationjava.model.SessionRecord;
import com.github.guoyyit.multisigaggregationjava.model.SessionState;
import com.github.guoyyit.multisigaggregationjava.store.AuditLog;
import com.github.guoyyit.multisigaggregationjava.store.KeyRepository;
import com.github.guoyyit.multisigaggregationjava.store.SessionRepository;
import org.bouncycastle.math.ec.ECPoint;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.UnaryOperator;
import java.util.concurrent.locks.ReentrantLock;

@Service
public class SessionService {

    private final ServiceProperties properties;
    private final KeyRepository keys;
    private final SessionRepository sessions;
    private final AggregationService aggregation;
    private final AuditLog audit;

    public SessionService(ServiceProperties properties, KeyRepository keys, SessionRepository sessions,
                          AggregationService aggregation, AuditLog audit) {
        this.properties = properties;
        this.keys = keys;
        this.sessions = sessions;
        this.aggregation = aggregation;
        this.audit = audit;
    }

    /**
     * 创建会话：创建时校验全部参与方公钥仍为 ACTIVE，并固定聚合公钥快照。
     */
    public SessionRecord create(String sessionId, String messageHex,
                                List<String> participantKeyIds, String retryOf) {
        String id = (sessionId == null || sessionId.isBlank())
                ? UUID.randomUUID().toString() : sessionId;
        if (!id.matches("[A-Za-z0-9._-]{1,128}")) {
            throw new ServiceException(ErrorCode.VALIDATION_ERROR, "非法 sessionId");
        }
        if (messageHex == null || messageHex.isBlank()) {
            throw new ServiceException(ErrorCode.INVALID_MESSAGE);
        }
        try {
            Hex.decode(messageHex);
        } catch (IllegalArgumentException ex) {
            throw new ServiceException(ErrorCode.INVALID_MESSAGE, "消息不是合法 hex");
        }
        if (participantKeyIds == null || participantKeyIds.isEmpty()) {
            throw new ServiceException(ErrorCode.VALIDATION_ERROR, "参与方不能为空");
        }
        List<String> distinct = participantKeyIds.stream().distinct().toList();
        if (distinct.size() != participantKeyIds.size()) {
            throw new ServiceException(ErrorCode.VALIDATION_ERROR, "参与方存在重复 keyId");
        }
        List<String> participantIds = new ArrayList<>(distinct);
        participantIds.forEach(keyId -> {
            if (keys.findById(keyId).isEmpty()) {
                throw new ServiceException(ErrorCode.KEY_NOT_FOUND, "参与方不存在: " + keyId);
            }
        });
        String aggregatePubHex = aggregation.aggregatePublicHex(participantIds);

        ReentrantLock lock = sessions.lock(id);
        lock.lock();
        try {
            if (sessions.findById(id).isPresent()) {
                throw new ServiceException(ErrorCode.DUPLICATE_KEY_ID, "sessionId 已存在");
            }
            int attempt = 1;
            if (retryOf != null && !retryOf.isBlank()) {
                SessionRecord parent = sessions.findById(retryOf)
                        .orElseThrow(() -> new ServiceException(ErrorCode.SESSION_NOT_FOUND,
                                "被重试会话不存在: " + retryOf));
                if (parent.state() != SessionState.FAILED_RETRYABLE
                        && parent.state() != SessionState.EXPIRED) {
                    throw new ServiceException(ErrorCode.SESSION_NOT_RETRYABLE,
                            "仅 FAILED_RETRYABLE 或 EXPIRED 会话可重试");
                }
                if (parent.attempt() >= properties.getMaxAttempts()) {
                    throw new ServiceException(ErrorCode.SESSION_NOT_RETRYABLE,
                            "已达最大重试次数 " + properties.getMaxAttempts());
                }
                attempt = parent.attempt() + 1;
            }
            long now = System.currentTimeMillis();
            SessionRecord session = new SessionRecord(
                    id, messageHex, participantIds, aggregatePubHex,
                    SessionState.COLLECTING_COMMITMENTS, FailureReason.NONE,
                    now, now + properties.getSessionTtlSeconds() * 1000L, 0L,
                    Hex.encode(Musig.sessionSalt()),
                    new LinkedHashMap<>(), new LinkedHashMap<>(), new LinkedHashMap<>(),
                    null, retryOf == null || retryOf.isBlank() ? null : retryOf, attempt);
            sessions.save(session);
            audit.append("SESSION_CREATED", null, id,
                    "participants=" + participantIds + ", retryOf=" + session.retryOf());
            return session;
        } finally {
            lock.unlock();
        }
    }

    private SessionRecord requireSession(String sessionId) {
        return sessions.findById(sessionId)
                .orElseThrow(() -> new ServiceException(ErrorCode.SESSION_NOT_FOUND));
    }

    private SessionRecord requireParticipant(String sessionId, String keyId) {
        SessionRecord session = requireSession(sessionId);
        if (keyId == null || !session.participantKeyIds().contains(keyId)) {
            throw new ServiceException(ErrorCode.UNKNOWN_PARTICIPANT,
                    keyId + " 不属于会话 " + sessionId);
        }
        return session;
    }

    private SessionRecord persist(SessionRecord session) {
        sessions.save(session);
        return session;
    }

    private SessionRecord fail(SessionRecord session, FailureReason reason,
                               ErrorCode code, String detail) {
        SessionState target = reason == FailureReason.CANCELLED
                ? SessionState.FAILED_CANCELLED : SessionState.FAILED_RETRYABLE;
        SessionRecord failed = new SessionRecord(
                session.sessionId(), session.messageHex(), session.participantKeyIds(),
                session.aggregatePubHex(), target, reason,
                session.createdAt(), session.deadlineMillis(), session.finalizedAt(),
                session.saltHex(), session.commitments(), session.nonces(),
                session.partialSignatures(), session.aggregateSignatureHex(),
                session.retryOf(), session.attempt());
        sessions.save(failed);
        audit.append("SESSION_FAILED", null, session.sessionId(),
                "reason=" + reason + ", detail=" + detail);
        throw new ServiceException(code, detail);
    }

    private SessionRecord copyWith(SessionRecord session,
                                   Map<String, String> commitments,
                                   Map<String, String> nonces,
                                   Map<String, String> partials,
                                   SessionState state,
                                   FailureReason reason) {
        SessionRecord updated = new SessionRecord(
                session.sessionId(), session.messageHex(), session.participantKeyIds(),
                session.aggregatePubHex(), state, reason,
                session.createdAt(), session.deadlineMillis(), session.finalizedAt(),
                session.saltHex(), Map.copyOf(commitments), Map.copyOf(nonces),
                Map.copyOf(partials), session.aggregateSignatureHex(),
                session.retryOf(), session.attempt());
        sessions.save(updated);
        return updated;
    }

    private SessionRecord withActiveSession(String sessionId, String keyId,
                                            List<SessionState> allowed,
                                            UnaryOperator<SessionRecord> action) {
        requireParticipant(sessionId, keyId);
        expireIfDue(sessionId);
        ReentrantLock lock = sessions.lock(sessionId);
        lock.lock();
        try {
            SessionRecord session = requireSession(sessionId);
            if (!allowed.contains(session.state())) {
                throw new ServiceException(ErrorCode.SESSION_NOT_ACTIVE,
                        "会话状态 " + session.state() + " 不允许该操作");
            }
            return action.apply(session);
        } finally {
            lock.unlock();
        }
    }

    private String keyIdForPoint(SessionRecord session, ECPoint point) {
        String target = Hex.encode(Schnorr.compress(point));
        for (String keyId : session.participantKeyIds()) {
            PublicKeyRecord record = keys.findById(keyId).orElse(null);
            if (record != null && KeyService.canonicalHex(record.pubHex()).equals(target)) {
                return keyId;
            }
        }
        throw new ServiceException(ErrorCode.INTERNAL_ERROR, "无法将公钥点映射回 keyId");
    }

    public SessionRecord submitCommitment(String sessionId, String keyId, String commitmentHex) {
        return withActiveSession(sessionId, keyId,
                List.of(SessionState.COLLECTING_COMMITMENTS), session -> {
                    String canonical;
                    try {
                        canonical = Hex.encode(Hex.decode(commitmentHex));
                    } catch (IllegalArgumentException ex) {
                        return fail(session, FailureReason.INVALID_COMMITMENT,
                                ErrorCode.INVALID_PARTIAL_SIGNATURE, "承诺不是合法 hex");
                    }
                    if (canonical.length() != 64) {
                        return fail(session, FailureReason.INVALID_COMMITMENT,
                                ErrorCode.INVALID_PARTIAL_SIGNATURE, "承诺必须为 32 字节");
                    }
                    String existing = session.commitments().get(keyId);
                    if (existing != null) {
                        if (existing.equals(canonical)) {
                            return session;
                        }
                        return fail(session, FailureReason.NONCE_REUSE,
                                ErrorCode.COMMITMENT_DUPLICATE,
                                keyId + " 已提交不同承诺，疑似随机数重用");
                    }
                    if (session.commitments().containsValue(canonical)) {
                        return fail(session, FailureReason.NONCE_REUSE,
                                ErrorCode.COMMITMENT_DUPLICATE,
                                "会话内检测到相同承诺（随机数重用）");
                    }
                    Map<String, String> commitments = new LinkedHashMap<>(session.commitments());
                    commitments.put(keyId, canonical);
                    return copyWith(session, commitments, session.nonces(),
                            session.partialSignatures(), SessionState.COLLECTING_COMMITMENTS,
                            FailureReason.NONE);
                });
    }

    public SessionRecord submitNonce(String sessionId, String keyId, String nonceHex) {
        requireParticipant(sessionId, keyId);
        expireIfDue(sessionId);
        ReentrantLock lock = sessions.lock(sessionId);
        lock.lock();
        try {
            SessionRecord session = requireSession(sessionId);
            SessionState state = session.state();
            if (state != SessionState.COLLECTING_COMMITMENTS
                    && state != SessionState.COMMITMENTS_FINALIZED
                    && state != SessionState.COLLECTING_SIGNATURES) {
                throw new ServiceException(ErrorCode.SESSION_NOT_ACTIVE,
                        "会话状态为 " + state);
            }
            String canonical;
            try {
                canonical = KeyService.canonicalHex(nonceHex);
            } catch (RuntimeException ex) {
                return persist(fail(session, FailureReason.INVALID_NONCE,
                        ErrorCode.INVALID_PARTIAL_SIGNATURE, "随机数编码无效"));
            }
            ECPoint point;
            try {
                point = Schnorr.parsePoint(Hex.decode(canonical));
            } catch (RuntimeException ex) {
                return persist(fail(session, FailureReason.INVALID_NONCE,
                        ErrorCode.INVALID_PARTIAL_SIGNATURE, "随机数点无效: " + ex.getMessage()));
            }

            String existingNonce = session.nonces().get(keyId);
            if (existingNonce != null) {
                if (existingNonce.equals(canonical)) {
                    return session;
                }
                return persist(fail(session, FailureReason.NONCE_REUSE,
                        ErrorCode.NONCE_REUSE, keyId + " 重复公开不同随机数"));
            }
            if (session.nonces().containsValue(canonical)) {
                return persist(fail(session, FailureReason.NONCE_REUSE,
                        ErrorCode.DUPLICATE_NONCE, "会话内出现重复随机数点"));
            }
            String committed = session.commitments().get(keyId);
            if (committed == null) {
                throw new ServiceException(ErrorCode.SESSION_NOT_ACTIVE,
                        keyId + " 尚未提交承诺");
            }
            String expected = Hex.encode(Musig.commitment(
                    sessionId, Schnorr.compress(point), Hex.decode(session.saltHex())));
            if (!committed.equals(expected)) {
                return persist(fail(session, FailureReason.INVALID_NONCE,
                        ErrorCode.NONCE_COMMITMENT_MISMATCH,
                        keyId + " 公开随机数与承诺不一致"));
            }

            ReentrantLock ledgerLock = sessions.nonceLedgerLock();
            ledgerLock.lock();
            try {
                if (!sessions.rememberNonce(keyId, sessionId, canonical)) {
                    return persist(fail(session, FailureReason.NONCE_REUSE,
                            ErrorCode.NONCE_REUSE,
                            keyId + " 的随机数已在其他会话使用（跨会话重用）"));
                }
            } finally {
                ledgerLock.unlock();
            }

            Map<String, String> nonces = new LinkedHashMap<>(session.nonces());
            nonces.put(keyId, canonical);
            SessionState newState = state == SessionState.COLLECTING_COMMITMENTS
                    ? SessionState.COMMITMENTS_FINALIZED : state;
            long finalizedAt = session.finalizedAt();
            if (nonces.size() == session.participantKeyIds().size()) {
                newState = SessionState.COLLECTING_SIGNATURES;
                finalizedAt = System.currentTimeMillis();
            }
            SessionRecord updated = new SessionRecord(
                    session.sessionId(), session.messageHex(), session.participantKeyIds(),
                    session.aggregatePubHex(), newState, FailureReason.NONE,
                    session.createdAt(), session.deadlineMillis(), finalizedAt,
                    session.saltHex(), session.commitments(), Map.copyOf(nonces),
                    session.partialSignatures(), session.aggregateSignatureHex(),
                    session.retryOf(), session.attempt());
            return persist(updated);
        } finally {
            lock.unlock();
        }
    }

    public SessionRecord submitPartial(String sessionId, String keyId, String partialHex) {
        SessionRecord current = sessions.findById(sessionId).orElse(null);
        if (current != null && current.state() == SessionState.COMPLETED) {
            String already = current.partialSignatures().get(keyId);
            String canonical = KeyService.canonicalHex(partialHex);
            if (already != null && already.equals(canonical)) {
                return current;
            }
            throw new ServiceException(ErrorCode.SESSION_NOT_ACTIVE, "会话已完成");
        }
        return withActiveSession(sessionId, keyId,
                List.of(SessionState.COLLECTING_SIGNATURES), session -> {
                    String canonical;
                    BigInteger sPart;
                    ECPoint nonce;
                    try {
                        canonical = KeyService.canonicalHex(partialHex);
                        Schnorr.ParsedSignature parsed =
                                Schnorr.parseSignature(Hex.decode(canonical));
                        sPart = parsed.s();
                        nonce = parsed.nonce();
                    } catch (RuntimeException ex) {
                        return fail(session, FailureReason.INVALID_PARTIAL_SIGNATURE,
                                ErrorCode.INVALID_PARTIAL_SIGNATURE,
                                "部分签名编码无效: " + ex.getMessage());
                    }
                    String signerNonceHex = session.nonces().get(keyId);
                    if (signerNonceHex == null
                            || !signerNonceHex.equals(Hex.encode(Schnorr.compress(nonce)))) {
                        return fail(session, FailureReason.INVALID_PARTIAL_SIGNATURE,
                                ErrorCode.INVALID_PARTIAL_SIGNATURE,
                                keyId + " 部分签名中的随机数与其公开随机数不一致");
                    }
                    String existing = session.partialSignatures().get(keyId);
                    if (existing != null) {
                        if (existing.equals(canonical)) {
                            return session;
                        }
                        return fail(session, FailureReason.INVALID_PARTIAL_SIGNATURE,
                                ErrorCode.INVALID_PARTIAL_SIGNATURE,
                                keyId + " 提交了冲突的部分签名");
                    }

                    Map<String, String> tentative =
                            new LinkedHashMap<>(session.partialSignatures());
                    tentative.put(keyId, canonical);
                    SessionRecord candidate = copyWith(session, session.commitments(),
                            session.nonces(), tentative,
                            SessionState.COLLECTING_SIGNATURES, FailureReason.NONE);

                    byte[] message = Hex.decode(session.messageHex());
                    ECPoint nonceSum = aggregation.nonceSum(candidate);
                    List<ECPoint> sortedPoints = aggregation.sortedPointsOf(candidate);
                    ECPoint member = sortedPoints.stream()
                            .filter(point -> keyIdForPoint(candidate, point).equals(keyId))
                            .findFirst()
                            .orElseThrow(() -> new ServiceException(ErrorCode.UNKNOWN_PARTICIPANT));
                    if (!aggregation.verifyPartial(candidate, member, nonce, nonceSum,
                            message, sPart)) {
                        return fail(session, FailureReason.INVALID_PARTIAL_SIGNATURE,
                                ErrorCode.INVALID_PARTIAL_SIGNATURE,
                                keyId + " 的部分签名验证失败");
                    }

                    if (tentative.size() == session.participantKeyIds().size()) {
                        aggregation.aggregatePartials(sessionId);
                        return requireSession(sessionId);
                    }
                    return candidate;
                });
    }

    public SessionRecord cancel(String sessionId, String reason) {
        ReentrantLock lock = sessions.lock(sessionId);
        lock.lock();
        try {
            SessionRecord session = requireSession(sessionId);
            if (session.state() == SessionState.COMPLETED) {
                throw new ServiceException(ErrorCode.SESSION_NOT_ACTIVE, "已完成会话不能取消");
            }
            if (session.state() == SessionState.FAILED_CANCELLED) {
                return session;
            }
            SessionRecord cancelled = new SessionRecord(
                    session.sessionId(), session.messageHex(), session.participantKeyIds(),
                    session.aggregatePubHex(), SessionState.FAILED_CANCELLED, FailureReason.CANCELLED,
                    session.createdAt(), session.deadlineMillis(), session.finalizedAt(),
                    session.saltHex(), session.commitments(), session.nonces(),
                    session.partialSignatures(), session.aggregateSignatureHex(),
                    session.retryOf(), session.attempt());
            sessions.save(cancelled);
            audit.append("SESSION_CANCELLED", null, sessionId,
                    reason == null ? "" : reason);
            return cancelled;
        } finally {
            lock.unlock();
        }
    }

    /**
     * 重试语义确定：仅 FAILED_RETRYABLE 可重试；取消（人为）不可重试；
     * 重试创建新会话与新 sessionId，随机数账本确保旧随机数不会被复用。
     */
    public SessionRecord retry(String sessionId) {
        SessionRecord session = requireSession(sessionId);
        if (session.state() != SessionState.FAILED_RETRYABLE
                && session.state() != SessionState.EXPIRED) {
            throw new ServiceException(ErrorCode.SESSION_NOT_RETRYABLE,
                    "会话状态为 " + session.state()
                            + "，仅 FAILED_RETRYABLE 或 EXPIRED 可重试");
        }
        if (session.attempt() >= properties.getMaxAttempts()) {
            throw new ServiceException(ErrorCode.SESSION_NOT_RETRYABLE,
                    "已达最大重试次数 " + properties.getMaxAttempts());
        }
        String newId = sessionId + "-r" + (session.attempt() + 1);
        return create(newId, session.messageHex(), session.participantKeyIds(), sessionId);
    }

    /**
     * 超时策略：未完成会话一旦越过 deadline 即转为 EXPIRED（归入可重试失败），
     * 已完成或已终结会话保持不变。
     */
    public SessionRecord expireIfDue(String sessionId) {
        ReentrantLock lock = sessions.lock(sessionId);
        lock.lock();
        try {
            SessionRecord session = sessions.findById(sessionId).orElse(null);
            if (session == null) {
                throw new ServiceException(ErrorCode.SESSION_NOT_FOUND);
            }
            if (isOpen(session.state()) && System.currentTimeMillis() > session.deadlineMillis()) {
                SessionRecord expired = new SessionRecord(
                        session.sessionId(), session.messageHex(), session.participantKeyIds(),
                        session.aggregatePubHex(), SessionState.EXPIRED, FailureReason.TIMEOUT,
                        session.createdAt(), session.deadlineMillis(), session.finalizedAt(),
                        session.saltHex(), session.commitments(), session.nonces(),
                        session.partialSignatures(), session.aggregateSignatureHex(),
                        session.retryOf(), session.attempt());
                sessions.save(expired);
                audit.append("SESSION_EXPIRED", null, sessionId, "deadlineMillis="
                        + session.deadlineMillis());
                throw new ServiceException(ErrorCode.SESSION_EXPIRED);
            }
            return session;
        } finally {
            lock.unlock();
        }
    }

    public SessionRecord get(String sessionId) {
        SessionRecord session = sessions.findById(sessionId)
                .orElseThrow(() -> new ServiceException(ErrorCode.SESSION_NOT_FOUND));
        if (isOpen(session.state()) && System.currentTimeMillis() > session.deadlineMillis()) {
            return expireIfDue(sessionId);
        }
        return session;
    }

    private static boolean isOpen(SessionState state) {
        return state == SessionState.COLLECTING_COMMITMENTS
                || state == SessionState.COMMITMENTS_FINALIZED
                || state == SessionState.COLLECTING_SIGNATURES;
    }
}
