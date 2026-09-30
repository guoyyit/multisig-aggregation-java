package com.github.guoyyit.multisigaggregationjava.service;

import com.github.guoyyit.multisigaggregationjava.model.SessionRecord;
import com.github.guoyyit.multisigaggregationjava.store.SessionRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
public class SessionSweeper {

    private final SessionRepository sessions;
    private final SessionService sessionService;

    public SessionSweeper(SessionRepository sessions, SessionService sessionService) {
        this.sessions = sessions;
        this.sessionService = sessionService;
    }

    @Scheduled(fixedDelayString = "${multisig.sweep-millis:5000}")
    public void sweepExpired() {
        for (SessionRecord session : sessions.findAll()) {
            try {
                sessionService.expireIfDue(session.sessionId());
            } catch (RuntimeException ignored) {
                // 已过期会抛出 SESSION_EXPIRED，属于预期；其他异常不影响扫描继续。
            }
        }
    }
}
