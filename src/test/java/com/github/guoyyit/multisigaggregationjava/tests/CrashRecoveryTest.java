package com.github.guoyyit.multisigaggregationjava.tests;

import com.github.guoyyit.multisigaggregationjava.core.Hex;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

class CrashRecoveryTest extends ServiceTestBase {

    @Test
    void incompleteSessionMarkedFailedAfterRestartThenRetryCompletes(@TempDir Path tempDir) {
        List<LocalSigner> signers;
        String msg = Hex.encode("crash-msg".getBytes(StandardCharsets.UTF_8));

        Context before = startContext(tempDir);
        try {
            signers = MultisigFlowTest.registerSigners(before, List.of("a", "b"));
            SessionRecord session = before.sessionService()
                    .create("crash-1", msg, List.of("a", "b"), null);
            before.sessionService().submitCommitment("crash-1", "a",
                    signers.get(0).commitment("crash-1", session.saltHex()));
        } finally {
            before.close();
        }

        Context after = startContext(tempDir);
        try {
            SessionRecord recovered = after.sessionService().get("crash-1");
            assertEquals(SessionState.FAILED_RETRYABLE, recovered.state());
            assertEquals(FailureReason.RECOVERY_ABORTED, recovered.failureReason());
            assertTrue(recovered.aggregateSignatureHex() == null,
                    "重启后绝不把部分聚合当作完整签名返回");

            SessionRecord retried = after.sessionService().retry("crash-1");
            SessionRecord completed = MultisigFlowTest.runProtocol(after, signers, retried);
            assertEquals(SessionState.COMPLETED, completed.state());
            assertTrue(after.aggregation().verifyAggregate(
                    msg, completed.aggregatePubHex(), completed.aggregateSignatureHex()));

            boolean hasRecoveryAudit = after.auditLog().entries().stream()
                    .anyMatch(entry -> "SESSION_RECOVERED".equals(entry.action()));
            assertTrue(hasRecoveryAudit, "恢复动作必须可审计");
        } finally {
            after.close();
        }
    }
}
