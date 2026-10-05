package com.github.guoyyit.multisigaggregationjava.tests;

import com.github.guoyyit.multisigaggregationjava.core.Hex;
import com.github.guoyyit.multisigaggregationjava.model.AuditEntry;
import com.github.guoyyit.multisigaggregationjava.model.FailureReason;
import com.github.guoyyit.multisigaggregationjava.model.SessionRecord;
import com.github.guoyyit.multisigaggregationjava.model.SessionState;
import com.github.guoyyit.multisigaggregationjava.signer.LocalSigner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OfflineTimeoutTest extends ServiceTestBase {

    private static String msg() {
        return Hex.encode("offline-timeout".getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void explicitOfflineIsDistinguishableRetryableAndNotOverwrittenByTimeout(
            @TempDir Path tempDir) throws Exception {
        Context context = startContext(tempDir);
        try {
            MultisigFlowTest.registerSigners(context, List.of("a", "b"));
            SessionRecord session = context.sessionService()
                    .create("off-1", msg(), List.of("a", "b"), null);

            SessionRecord offline = context.sessionService()
                    .markParticipantOffline("off-1", "b", "participant unreachable");
            assertEquals(SessionState.FAILED_RETRYABLE, offline.state());
            assertEquals(FailureReason.OFFLINE, offline.failureReason(),
                    "离线必须是与超时可区分的失败原因");

            // 越过截止时间后再触发扫描与查询，离线原因不得被改写为 TIMEOUT。
            Thread.sleep(2_500);
            context.sessionService().expireIfDue("off-1");
            SessionRecord queried = context.sessionService().get("off-1");
            assertEquals(FailureReason.OFFLINE, queried.failureReason());

            boolean auditedOffline = context.auditLog().entries().stream()
                    .anyMatch(entry -> "SESSION_FAILED".equals(entry.action())
                            && entry.detail().contains("reason=OFFLINE")
                            && "b".equals(entry.keyId()));
            assertTrue(auditedOffline, "离线事件必须可审计且可区分");

            SessionRecord retried = context.sessionService().retry("off-1");
            List<LocalSigner> signers = List.of(
                    LocalSigner.load("a", context.fileStore()),
                    LocalSigner.load("b", context.fileStore()));
            SessionRecord completed = MultisigFlowTest.runProtocol(context, signers, retried);
            assertEquals(SessionState.COMPLETED, completed.state(),
                    "离线会话保持可重试");
        } finally {
            context.close();
        }
    }

    @Test
    void timeoutFailureReasonIsDistinctFromOffline(@TempDir Path tempDir) throws Exception {
        Context context = startContext(tempDir);
        try {
            MultisigFlowTest.registerSigners(context, List.of("a", "b"));
            context.sessionService().create("to-1", msg(), List.of("a", "b"), null);
            Thread.sleep(2_500);
            SessionRecord expired;
            try {
                expired = context.sessionService().get("to-1");
            } catch (com.github.guoyyit.multisigaggregationjava.core.ServiceException timeoutSignal) {
                assertEquals(
                        com.github.guoyyit.multisigaggregationjava.core.ErrorCode.SESSION_EXPIRED,
                        timeoutSignal.errorCode());
                expired = context.sessionService().get("to-1");
            }
            assertEquals(SessionState.EXPIRED, expired.state());
            assertEquals(FailureReason.TIMEOUT, expired.failureReason());
            SessionRecord retried = context.sessionService().retry("to-1");
            assertEquals(SessionState.COLLECTING_COMMITMENTS, retried.state(),
                    "超时会话保持可重试");
        } finally {
            context.close();
        }
    }

    @Test
    void restartRecoveryDistinguishesPastDeadlineFromInterrupted(@TempDir Path tempDir) {
        List<LocalSigner> signers;
        Context before = startContext(tempDir);
        try {
            signers = MultisigFlowTest.registerSigners(before, List.of("a", "b"));
            // 未越期会话。
            before.sessionService().create("rec-fresh", msg(), List.of("a", "b"), null);
            // 已越期会话：先创建，再直接把 deadline 改成过去。
            SessionRecord due = before.sessionService()
                    .create("rec-due", msg(), List.of("a", "b"), null);
            SessionRecord pastDeadline = new SessionRecord(
                    due.sessionId(), due.messageHex(), due.participantKeyIds(),
                    due.aggregatePubHex(), due.state(), due.failureReason(),
                    due.createdAt(), 1L, due.finalizedAt(), due.saltHex(),
                    due.commitments(), due.nonces(), due.partialSignatures(),
                    due.aggregateSignatureHex(), due.retryOf(), due.attempt());
            before.applicationContext()
                    .getBean(com.github.guoyyit.multisigaggregationjava.store.SessionRepository.class)
                    .save(pastDeadline);
        } finally {
            before.close();
        }

        Context after = startContext(tempDir);
        try {
            assertEquals(FailureReason.RECOVERY_INTERRUPTED,
                    after.sessionService().get("rec-fresh").failureReason());
            assertEquals(FailureReason.RECOVERY_TIMEOUT,
                    after.sessionService().get("rec-due").failureReason(),
                    "重启时已越过截止时间的会话必须给出可区分的恢复原因");

            List<String> recoveryDetails = after.auditLog().entries().stream()
                    .filter(entry -> "SESSION_RECOVERED".equals(entry.action()))
                    .map(AuditEntry::detail).toList();
            assertTrue(recoveryDetails.stream().anyMatch(d -> d.contains("reason=RECOVERY_TIMEOUT")));
            assertTrue(recoveryDetails.stream()
                    .anyMatch(d -> d.contains("reason=RECOVERY_INTERRUPTED")));

            // 两类恢复会话都保持可重试。
            for (SessionRecord recovered : List.of(
                    after.sessionService().get("rec-fresh"),
                    after.sessionService().get("rec-due"))) {
                assertEquals(SessionState.FAILED_RETRYABLE, recovered.state());
                assertFalse(recovered.failureReason() == FailureReason.NONE);
            }

            SessionRecord retried = after.sessionService().retry("rec-fresh");
            SessionRecord completed = MultisigFlowTest.runProtocol(after, signers, retried);
            assertEquals(SessionState.COMPLETED, completed.state());
        } finally {
            after.close();
        }
    }

    @Test
    void repeatedRecoveryInSameProcessAuditsOnce(@TempDir Path tempDir) {
        Context context = startContext(tempDir);
        try {
            MultisigFlowTest.registerSigners(context, List.of("a", "b"));
            context.sessionService().create("rec-once", msg(), List.of("a", "b"), null);

            var recovery = context.applicationContext()
                    .getBean(com.github.guoyyit.multisigaggregationjava.service.RecoveryService.class);
            // @PostConstruct 已执行过；再次手动调用不得再产生任何恢复审计。
            int beforeCount = (int) context.auditLog().entries().stream()
                    .filter(entry -> entry.action().startsWith("RECOVERY")
                            || "SESSION_RECOVERED".equals(entry.action()))
                    .count();
            recovery.runRecovery(System.currentTimeMillis());
            int afterCount = (int) context.auditLog().entries().stream()
                    .filter(entry -> entry.action().startsWith("RECOVERY")
                            || "SESSION_RECOVERED".equals(entry.action()))
                    .count();
            assertEquals(beforeCount, afterCount, "同一恢复动作重复执行只产生一次审计记录");
        } finally {
            context.close();
        }
    }
}
