package com.github.guoyyit.multisigaggregationjava.service;

import com.github.guoyyit.multisigaggregationjava.model.FailureReason;
import com.github.guoyyit.multisigaggregationjava.model.SessionRecord;
import com.github.guoyyit.multisigaggregationjava.model.SessionState;
import com.github.guoyyit.multisigaggregationjava.store.AuditLog;
import com.github.guoyyit.multisigaggregationjava.store.SessionRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.util.concurrent.atomic.AtomicBoolean;

@Service
public class RecoveryService {

    private final SessionRepository sessions;
    private final AuditLog audit;
    private final AtomicBoolean recoveredThisProcess = new AtomicBoolean(false);

    public RecoveryService(SessionRepository sessions, AuditLog audit) {
        this.sessions = sessions;
        this.audit = audit;
    }

    /**
     * 崩溃恢复：重启后按是否越过截止时间，把未终结会话显式标记为
     * FAILED_RETRYABLE / RECOVERY_TIMEOUT 或 RECOVERY_INTERRUPTED。
     * 旧会话的随机数已在随机数账本中登记，重试必须生成新随机数，
     * 且任何部分聚合都不会被当作完整签名对外返回。
     */
    @PostConstruct
    public void recover() {
        runRecovery(System.currentTimeMillis());
    }

    /**
     * 崩溃恢复：未完成会话按崩溃时刻是否已越过 deadline 给出可区分原因——
     * 已越过的为 RECOVERY_TIMEOUT，未越过即被中断的为 RECOVERY_INTERRUPTED；
     * 两者都标记为 FAILED_RETRYABLE。每个进程仅执行一次；
     * 同一进程内重复调用不会再产生任何审计记录（恢复动作恰好一次）。
     */
    public void runRecovery(long nowMillis) {
        if (!recoveredThisProcess.compareAndSet(false, true)) {
            return;
        }
        int recovered = 0;
        int timedOut = 0;
        int interrupted = 0;
        for (SessionRecord session : sessions.findAll()) {
            if (isOpen(session.state())) {
                boolean pastDeadline = nowMillis > session.deadlineMillis();
                FailureReason reason = pastDeadline
                        ? FailureReason.RECOVERY_TIMEOUT : FailureReason.RECOVERY_INTERRUPTED;
                SessionRecord aborted = new SessionRecord(
                        session.sessionId(), session.messageHex(), session.participantKeyIds(),
                        session.aggregatePubHex(), SessionState.FAILED_RETRYABLE,
                        reason,
                        session.createdAt(), session.deadlineMillis(), session.finalizedAt(),
                        session.saltHex(), session.commitments(), session.nonces(),
                        session.partialSignatures(), session.aggregateSignatureHex(),
                        session.retryOf(), session.attempt());
                sessions.save(aborted);
                audit.append("SESSION_RECOVERED", null, session.sessionId(),
                        "reason=" + reason + ", pastDeadline=" + pastDeadline
                                + ", deadlineMillis=" + session.deadlineMillis());
                recovered++;
                if (pastDeadline) {
                    timedOut++;
                } else {
                    interrupted++;
                }
            }
        }
        if (recovered > 0) {
            audit.append("RECOVERY_COMPLETE", null, null,
                    "abortedSessions=" + recovered
                            + ", timedOut=" + timedOut + ", interrupted=" + interrupted);
        }
    }

    private static boolean isOpen(SessionState state) {
        return state == SessionState.COLLECTING_COMMITMENTS
                || state == SessionState.COMMITMENTS_FINALIZED
                || state == SessionState.COLLECTING_SIGNATURES;
    }
}
