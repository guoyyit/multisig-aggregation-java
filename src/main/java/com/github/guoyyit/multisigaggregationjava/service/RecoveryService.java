package com.github.guoyyit.multisigaggregationjava.service;

import com.github.guoyyit.multisigaggregationjava.store.PersistentStateStore;

import com.github.guoyyit.multisigaggregationjava.domain.FailureReason;
import com.github.guoyyit.multisigaggregationjava.domain.SessionStatus;
import com.github.guoyyit.multisigaggregationjava.domain.SignSession;

import java.util.ArrayList;
import java.util.List;

/**
 * Crash recovery on startup. In-flight OPEN sessions are either resumed when
 * still within their deadline or deterministically marked FAILED with reason
 * RESTART_RECOVERY so they must be explicitly retried with fresh nonces.
 */
public class RecoveryService {

    private final PersistentStateStore store;
    private final boolean markIncompleteFailed;

    public RecoveryService(PersistentStateStore store, boolean markIncompleteFailed) {
        this.store = store;
        this.markIncompleteFailed = markIncompleteFailed;
        this.store.load();
    }

    /** Recover persisted state. Returns ids of sessions marked failed. */
    public List<String> recoverOnStartup(long now) {
        List<String> marked = new ArrayList<>();
        store.lock().writeLock().lock();
        try {
            for (SignSession session : store.allSessions()) {
                if (session.getStatus() != SessionStatus.OPEN) {
                    continue;
                }
                if (markIncompleteFailed || session.getDeadlineAt() <= now) {
                    session.setStatus(SessionStatus.FAILED);
                    session.setFailureReason(FailureReason.RESTART_RECOVERY);
                    session.setRecoveredAfterRestart(true);
                    session.setUpdatedAt(now);
                    store.putSession(session);
                    marked.add(session.getSessionId());
                }
            }
            return marked;
        } finally {
            store.lock().writeLock().unlock();
        }
    }
}
