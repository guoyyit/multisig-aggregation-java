package com.github.guoyyit.multisigaggregationjava.service;

import com.github.guoyyit.multisigaggregationjava.model.FailureReason;
import com.github.guoyyit.multisigaggregationjava.model.SessionRecord;
import com.github.guoyyit.multisigaggregationjava.model.SessionState;
import com.github.guoyyit.multisigaggregationjava.store.AuditLog;
import com.github.guoyyit.multisigaggregationjava.store.SessionRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

@Service
public class RecoveryService {

    private final SessionRepository sessions;
    private final AuditLog audit;

    public RecoveryService(SessionRepository sessions, AuditLog audit) {
        this.sessions = sessions;
        this.audit = audit;
    }

    /**
     * 崩溃恢复：重启后把所有未终结会话显式标记为 FAILED_RETRYABLE / RECOVERY_ABORTED。
     * 旧会话的随机数已在随机数账本中登记，重试必须生成新随机数，
     * 且任何部分聚合都不会被当作完整签名对外返回。
     *
     * 恢复原因按是否已越过截止时间区分：
     * 已越过 deadline 的会话按超时处理（EXPIRED / TIMEOUT，审计 SESSION_EXPIRED），
     * 未越过的按崩溃中断处理（FAILED_RETRYABLE / RECOVERY_ABORTED，审计 SESSION_RECOVERED）。
     * 恢复动作以会话终态为幂等锚点：同一会话只会被转换并审计一次，
     * 重复执行 recover() 不会产生重复审计记录。
     */
    @PostConstruct
    public void recover() {
        int aborted = 0;
        int expired = 0;
        long now = System.currentTimeMillis();
        for (SessionRecord session : sessions.findAll()) {
            if (isOpen(session.state())) {
                if (now > session.deadlineMillis()) {
                    SessionRecord expiredSession = new SessionRecord(
                            session.sessionId(), session.messageHex(), session.participantKeyIds(),
                            session.aggregatePubHex(), SessionState.EXPIRED,
                            FailureReason.TIMEOUT,
                            session.createdAt(), session.deadlineMillis(), session.finalizedAt(),
                            session.saltHex(), session.commitments(), session.nonces(),
                            session.partialSignatures(), session.aggregateSignatureHex(),
                            session.retryOf(), session.attempt());
                    sessions.save(expiredSession);
                    audit.append("SESSION_EXPIRED", null, session.sessionId(),
                            "trigger=recovery, deadlineMillis=" + session.deadlineMillis());
                    expired++;
                } else {
                    SessionRecord abortedSession = new SessionRecord(
                            session.sessionId(), session.messageHex(), session.participantKeyIds(),
                            session.aggregatePubHex(), SessionState.FAILED_RETRYABLE,
                            FailureReason.RECOVERY_ABORTED,
                            session.createdAt(), session.deadlineMillis(), session.finalizedAt(),
                            session.saltHex(), session.commitments(), session.nonces(),
                            session.partialSignatures(), session.aggregateSignatureHex(),
                            session.retryOf(), session.attempt());
                    sessions.save(abortedSession);
                    audit.append("SESSION_RECOVERED", null, session.sessionId(),
                            "重启后未完成会话标记为 FAILED_RETRYABLE");
                    aborted++;
                }
            }
        }
        if (aborted + expired > 0) {
            audit.append("RECOVERY_COMPLETE", null, null,
                    "abortedSessions=" + aborted + ", expiredSessions=" + expired);
        }
    }

    private static boolean isOpen(SessionState state) {
        return state == SessionState.COLLECTING_COMMITMENTS
                || state == SessionState.COMMITMENTS_FINALIZED
                || state == SessionState.COLLECTING_SIGNATURES;
    }
}
