package com.github.guoyyit.multisigaggregationjava.service;

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
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class AggregationService {

    private final KeyService keyService;
    private final KeyRepository keys;
    private final SessionRepository sessions;
    private final AuditLog audit;

    public AggregationService(KeyService keyService, KeyRepository keys,
                              SessionRepository sessions, AuditLog audit) {
        this.keyService = keyService;
        this.keys = keys;
        this.sessions = sessions;
        this.audit = audit;
    }

    public static class SortedKeys {
        public final List<PublicKeyRecord> records;
        public final List<ECPoint> points;

        SortedKeys(List<PublicKeyRecord> records, List<ECPoint> points) {
            this.records = records;
            this.points = points;
        }
    }

    /**
     * 按压缩公钥排序的参与方视图，保证 KeyAgg 系数与会话内承诺顺序无关。
     */
    public SortedKeys sortedKeys(List<String> keyIds) {
        if (keyIds == null || keyIds.isEmpty()) {
            throw new ServiceException(ErrorCode.VALIDATION_ERROR, "参与方不能为空");
        }
        List<PublicKeyRecord> records = keyIds.stream().map(keyService::requireActive).toList();
        List<ECPoint> points = records.stream()
                .map(record -> KeyService.parsePublicKey(record.pubHex()))
                .sorted(Comparator.comparing(p -> Hex.encode(Schnorr.compress(p))))
                .toList();
        List<ECPoint> sortedPoints = Musig.sortPoints(points);
        List<PublicKeyRecord> sortedRecords = new ArrayList<>();
        for (ECPoint point : sortedPoints) {
            String hex = Hex.encode(Schnorr.compress(point));
            sortedRecords.add(records.stream()
                    .filter(record -> KeyService.canonicalHex(record.pubHex()).equals(hex))
                    .findFirst()
                    .orElseThrow(() -> new ServiceException(ErrorCode.INTERNAL_ERROR)));
        }
        return new SortedKeys(sortedRecords, sortedPoints);
    }

    public ECPoint aggregatePublicKey(List<String> keyIds) {
        SortedKeys sorted = sortedKeys(keyIds);
        return Musig.aggregatePoint(sorted.points);
    }

    public String aggregatePublicHex(List<String> keyIds) {
        return Hex.encode(Schnorr.compress(aggregatePublicKey(keyIds)));
    }

    /**
     * 用已收集的全部部分签名构造最终签名并完成会话。
     * 任一参与方缺失都抛出 SESSION_INCOMPLETE，绝不返回不完整聚合。
     */
    public byte[] aggregatePartials(String sessionId) {
        SessionRecord session = sessions.findById(sessionId)
                .orElseThrow(() -> new ServiceException(ErrorCode.SESSION_NOT_FOUND));
        if (session.state() != SessionState.COLLECTING_SIGNATURES
                && session.state() != SessionState.COMPLETED) {
            throw new ServiceException(ErrorCode.SESSION_NOT_ACTIVE,
                    "会话状态为 " + session.state());
        }
        if (session.partialSignatures().size() != session.participantKeyIds().size()) {
            throw new ServiceException(ErrorCode.SESSION_INCOMPLETE,
                    "已收集 " + session.partialSignatures().size() + "/"
                            + session.participantKeyIds().size());
        }

        List<ECPoint> sortedPoints = sortedPointsOf(session);
        ECPoint nonceSum = nonceSum(session);
        byte[] message = Hex.decode(session.messageHex());

        BigInteger total = BigInteger.ZERO;
        for (ECPoint member : sortedPoints) {
            String keyId = keyIdForPoint(session, member);
            String partialHex = session.partialSignatures().get(keyId);
            if (partialHex == null) {
                throw new ServiceException(ErrorCode.SESSION_INCOMPLETE,
                        "缺少 " + keyId + " 的部分签名");
            }
            Schnorr.ParsedSignature parsed =
                    Schnorr.parseSignature(Hex.decode(partialHex));
            if (!verifyPartial(session, member, parsed.nonce(), nonceSum, message, parsed.s())) {
                throw new ServiceException(ErrorCode.INVALID_PARTIAL_SIGNATURE,
                        keyId + " 的部分签名无法通过验证");
            }
            total = total.add(parsed.s());
        }
        total = total.mod(Schnorr.curveOrder());
        byte[] signature = Schnorr.encodeSignature(nonceSum, total);
        String signatureHex = Hex.encode(signature);

        if (session.state() != SessionState.COMPLETED) {
            SessionRecord completed = new SessionRecord(
                    session.sessionId(), session.messageHex(), session.participantKeyIds(),
                    session.aggregatePubHex(), SessionState.COMPLETED, FailureReason.NONE,
                    session.createdAt(), session.deadlineMillis(), session.finalizedAt(),
                    session.saltHex(), session.commitments(), session.nonces(),
                    session.partialSignatures(), signatureHex, session.retryOf(), session.attempt());
            sessions.save(completed);
            audit.append("SESSION_COMPLETED", null, sessionId, "aggSig=" + signatureHex);
        }
        return signature;
    }

    public boolean verifyPartialsIndividually(String sessionId) {
        SessionRecord session = sessions.findById(sessionId)
                .orElseThrow(() -> new ServiceException(ErrorCode.SESSION_NOT_FOUND));
        if (session.partialSignatures().size() != session.participantKeyIds().size()) {
            return false;
        }
        List<ECPoint> sortedPoints = sortedPointsOf(session);
        ECPoint nonceSum = nonceSum(session);
        byte[] message = Hex.decode(session.messageHex());
        for (ECPoint member : sortedPoints) {
            String keyId = keyIdForPoint(session, member);
            Schnorr.ParsedSignature parsed = Schnorr.parseSignature(
                    Hex.decode(session.partialSignatures().get(keyId)));
            if (!verifyPartial(session, member, parsed.nonce(), nonceSum, message, parsed.s())) {
                return false;
            }
        }
        return true;
    }

    public boolean verifyAggregate(String messageHex, String aggregatePubHex, String signatureHex) {
        try {
            byte[] message = Hex.decode(messageHex);
            ECPoint aggregatePoint = Schnorr.parsePoint(Hex.decode(aggregatePubHex));
            byte[] signature = Hex.decode(signatureHex);
            return Schnorr.verifySchnorr(aggregatePoint, message, signature);
        } catch (RuntimeException ex) {
            return false;
        }
    }

    public boolean verifyFull(ECPoint publicKey, byte[] message, ECPoint nonce, BigInteger s) {
        return Schnorr.verifyFull(publicKey, message, nonce, s);
    }

    public ECPoint nonceSum(SessionRecord session) {
        List<ECPoint> sortedPoints = sortedPointsOf(session);
        ECPoint acc = Schnorr.generator().getCurve().getInfinity();
        for (ECPoint member : sortedPoints) {
            String keyId = keyIdForPoint(session, member);
            String nonceHex = session.nonces().get(keyId);
            if (nonceHex == null) {
                throw new ServiceException(ErrorCode.SESSION_NOT_READY,
                        keyId + " 尚未公开随机数");
            }
            acc = acc.add(Schnorr.parsePoint(Hex.decode(nonceHex)));
        }
        return acc.normalize();
    }

    public List<ECPoint> sortedPointsOf(SessionRecord session) {
        List<ECPoint> points = new ArrayList<>();
        for (String keyId : session.participantKeyIds()) {
            PublicKeyRecord record = keys.findById(keyId)
                    .orElseThrow(() -> new ServiceException(ErrorCode.KEY_NOT_FOUND,
                            "参与方公钥缺失: " + keyId));
            points.add(Schnorr.parsePoint(Hex.decode(record.pubHex())));
        }
        return Musig.sortPoints(points);
    }

    /**
     * 验证单个部分签名：s_i·G = R_i + e·a_i·X_i，其中 e = H(Rsum || Xagg || m)。
     */
    public boolean verifyPartial(SessionRecord session, ECPoint member,
                                 ECPoint ownNonce, ECPoint nonceSum,
                                 byte[] message, BigInteger sPart) {
        List<ECPoint> sortedPoints = sortedPointsOf(session);
        ECPoint effective = Musig.effectivePublicKey(sortedPoints, member);
        ECPoint aggregate = Musig.aggregatePoint(sortedPoints);
        BigInteger challenge = Schnorr.challenge(nonceSum, aggregate, message);
        ECPoint left = Schnorr.scalarBaseMult(sPart);
        ECPoint right = Schnorr.sum(ownNonce, effective.multiply(challenge));
        return left.equals(right);
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

    public Map<String, Object> sessionView(SessionRecord session) {
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("sessionId", session.sessionId());
        view.put("state", session.state().name());
        view.put("failureReason", session.failureReason().name());
        view.put("participantKeyIds", session.participantKeyIds());
        view.put("aggregatePubHex", session.aggregatePubHex());
        view.put("saltHex", session.saltHex());
        view.put("messageHex", session.messageHex());
        view.put("deadlineMillis", session.deadlineMillis());
        view.put("commitments", session.commitments());
        view.put("nonces", session.nonces());
        view.put("collectedPartials", session.partialSignatures().size());
        view.put("partialSignatures", session.partialSignatures());
        view.put("aggregateSignatureHex", session.aggregateSignatureHex());
        view.put("retryOf", session.retryOf());
        view.put("attempt", session.attempt());
        return view;
    }
}
