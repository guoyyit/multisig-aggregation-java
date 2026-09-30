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
     */
    @PostConstruct
    public void recover() {
        int recovered = 0;
        for (SessionRecord session : sessions.findAll()) {
            if (isOpen(session.state())) {
                SessionRecord aborted = new SessionRecord(
                        session.sessionId(), session.messageHex(), session.participantKeyIds(),
                        session.aggregatePubHex(), SessionState.FAILED_RETRYABLE,
                        FailureReason.RECOVERY_ABORTED,
                        session.createdAt(), session.deadlineMillis(), session.finalizedAt(),
                        session.saltHex(), session.commitments(), session.nonces(),
                        session.partialSignatures(), session.aggregateSignatureHex(),
                        session.retryOf(), session.attempt());
                sessions.save(aborted);
                audit.append("SESSION_RECOVERED", null, session.sessionId(),
                        "重启后未完成会话标记为 FAILED_RETRYABLE");
                recovered++;
            }
        }
        if (recovered > 0) {
            audit.append("RECOVERY_COMPLETE", null, null, "abortedSessions=" + recovered);
        }
    }

    private static boolean isOpen(SessionState state) {
        return state == SessionState.COLLECTING_COMMITMENTS
                || state == SessionState.COMMITMENTS_FINALIZED
                || state == SessionState.COLLECTING_SIGNATURES;
    }
}
