package com.github.guoyyit.multisigaggregationjava.tests;

import com.github.guoyyit.multisigaggregationjava.core.ErrorCode;
import com.github.guoyyit.multisigaggregationjava.core.Hex;
import com.github.guoyyit.multisigaggregationjava.core.ServiceException;
import com.github.guoyyit.multisigaggregationjava.model.AuditEntry;
import com.github.guoyyit.multisigaggregationjava.model.FailureReason;
import com.github.guoyyit.multisigaggregationjava.model.SessionRecord;
import com.github.guoyyit.multisigaggregationjava.model.SessionState;
import com.github.guoyyit.multisigaggregationjava.service.SessionSweeper;
import com.github.guoyyit.multisigaggregationjava.signer.LocalSigner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OfflineDistinctionTest extends ServiceTestBase {

    @Test
    void offlineMarkingIsDistinctAuditedAndNotOverwrittenByTimeout(@TempDir Path tempDir)
            throws Exception {
        Context context = startContext(tempDir);
        try {
            List<LocalSigner> signers = MultisigFlowTest.registerSigners(
                    context, List.of("off-a", "off-b"));
            String msg = Hex.encode("offline-msg".getBytes(StandardCharsets.UTF_8));
            context.sessionService().create("off-1", msg, List.of("off-a", "off-b"), null);

            SessionRecord offline = context.sessionService()
                    .markOffline("off-1", "off-b", "unreachable");
            assertEquals(SessionState.FAILED_RETRYABLE, offline.state());
            assertEquals(FailureReason.OFFLINE, offline.failureReason(),
                    "显式离线必须给出与超时可区分的原因");

            SessionRecord again = context.sessionService()
                    .markOffline("off-1", "off-b", "unreachable");
            assertEquals(FailureReason.OFFLINE, again.failureReason());
            long offlineAudits = context.auditLog().entries().stream()
                    .filter(e -> "SESSION_OFFLINE".equals(e.action()))
                    .count();
            assertEquals(1, offlineAudits, "重复标记同一离线状态只审计一次");
            AuditEntry offlineAudit = context.auditLog().entries().stream()
                    .filter(e -> "SESSION_OFFLINE".equals(e.action()))
                    .findFirst().orElseThrow();
            assertEquals("off-b", offlineAudit.keyId());
            assertEquals("off-1", offlineAudit.sessionId());

            Thread.sleep(2300);
            context.spring().getBean(SessionSweeper.class).sweepExpired();
            SessionRecord afterSweep = context.sessionService().get("off-1");
            assertEquals(SessionState.FAILED_RETRYABLE, afterSweep.state());
            assertEquals(FailureReason.OFFLINE, afterSweep.failureReason(),
                    "离线原因不得被随后的超时扫描覆盖或改写");

            SessionRecord retried = context.sessionService().retry("off-1");
            SessionRecord completed = MultisigFlowTest.runProtocol(context, signers, retried);
            assertEquals(SessionState.COMPLETED, completed.state(),
                    "离线失败的会话保持可重试");
        } finally {
            context.close();
        }
    }

    @Test
    void timedOutSessionRejectsOfflineMarking(@TempDir Path tempDir) throws Exception {
        Context context = startContext(tempDir);
        try {
            MultisigFlowTest.registerSigners(context, List.of("t-a", "t-b"));
            String msg = Hex.encode("timeout-only".getBytes(StandardCharsets.UTF_8));
            context.sessionService().create("t-1", msg, List.of("t-a", "t-b"), null);
            Thread.sleep(2300);
            assertThrows(ServiceException.class,
                    () -> context.sessionService().expireIfDue("t-1"));
            SessionRecord expired = context.sessionService().get("t-1");
            assertEquals(SessionState.EXPIRED, expired.state());
            assertEquals(FailureReason.TIMEOUT, expired.failureReason());

            ServiceException markAfterTimeout = assertThrows(ServiceException.class,
                    () -> context.sessionService().markOffline("t-1", "t-b", "late"));
            assertEquals(ErrorCode.SESSION_NOT_ACTIVE, markAfterTimeout.errorCode(),
                    "已超时终结的会话不接受离线标记，两类原因保持可区分");
            assertEquals(FailureReason.TIMEOUT,
                    context.sessionService().get("t-1").failureReason());
        } finally {
            context.close();
        }
    }

    @Test
    void recoveryReasonDependsOnDeadline(@TempDir Path tempDir) throws Exception {
        String msg = Hex.encode("recover-msg".getBytes(StandardCharsets.UTF_8));
        List<LocalSigner> signers;

        Context before = startContext(tempDir);
        try {
            signers = MultisigFlowTest.registerSigners(before, List.of("r-a", "r-b"));
            before.sessionService().create("rec-overdue", msg, List.of("r-a", "r-b"), null);
            Thread.sleep(2300);
            before.sessionService().create("rec-fresh", msg, List.of("r-a", "r-b"), null);
        } finally {
            before.close();
        }

        Context after = startContext(tempDir);
        try {
            SessionRecord overdue = after.sessionService().get("rec-overdue");
            assertEquals(SessionState.EXPIRED, overdue.state());
            assertEquals(FailureReason.TIMEOUT, overdue.failureReason(),
                    "恢复时已越过截止时间的会话必须按超时给出可区分原因");

            SessionRecord fresh = after.sessionService().get("rec-fresh");
            assertEquals(SessionState.FAILED_RETRYABLE, fresh.state());
            assertEquals(FailureReason.RECOVERY_ABORTED, fresh.failureReason(),
                    "恢复时未越过截止时间的会话必须按崩溃中断给出可区分原因");

            List<AuditEntry> entries = after.auditLog().entries();
            assertTrue(entries.stream().anyMatch(e -> "SESSION_EXPIRED".equals(e.action())
                            && "rec-overdue".equals(e.sessionId())
                            && e.detail().contains("trigger=recovery")),
                    "超时恢复必须留下可区分的审计");
            assertTrue(entries.stream().anyMatch(e -> "SESSION_RECOVERED".equals(e.action())
                            && "rec-fresh".equals(e.sessionId())),
                    "中断恢复必须留下可区分的审计");

            SessionRecord retried = after.sessionService().retry("rec-overdue");
            SessionRecord completed = MultisigFlowTest.runProtocol(after, signers, retried);
            assertEquals(SessionState.COMPLETED, completed.state(),
                    "超时恢复的会话保持可重试");
            SessionRecord retriedFresh = after.sessionService().retry("rec-fresh");
            assertEquals(SessionState.COLLECTING_COMMITMENTS, retriedFresh.state(),
                    "中断恢复的会话同样保持可重试");
        } finally {
            after.close();
        }
    }
}
