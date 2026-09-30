package com.github.guoyyit.multisigaggregationjava.tests;

import com.github.guoyyit.multisigaggregationjava.core.ErrorCode;
import com.github.guoyyit.multisigaggregationjava.core.Hex;
import com.github.guoyyit.multisigaggregationjava.core.ServiceException;
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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionLifecycleTest extends ServiceTestBase {

    @Test
    void offlineParticipantExpiresSessionAndRetrySucceeds(@TempDir Path tempDir) throws Exception {
        Context context = startContext(tempDir);
        try {
            List<LocalSigner> signers = MultisigFlowTest.registerSigners(
                    context, List.of("a", "b"));
            String msg = Hex.encode("timeout-msg".getBytes(StandardCharsets.UTF_8));
            context.sessionService().create("life-1", msg, List.of("a", "b"), null);
            context.sessionService().submitCommitment("life-1", "a",
                    signers.get(0).commitment("life-1",
                            context.sessionService().get("life-1").saltHex()));

            Thread.sleep(2300);

            ServiceException expired = assertThrows(ServiceException.class,
                    () -> context.sessionService().expireIfDue("life-1"));
            assertEquals(ErrorCode.SESSION_EXPIRED, expired.errorCode());
            SessionRecord session = context.sessionService().get("life-1");
            assertEquals(SessionState.EXPIRED, session.state());
            assertEquals(FailureReason.TIMEOUT, session.failureReason());
            assertTrue(session.aggregateSignatureHex() == null,
                    "超时时不得返回任何聚合签名");

            SessionRecord retried = context.sessionService().retry("life-1");
            assertNotEquals("life-1", retried.sessionId());
            assertEquals(2, retried.attempt());
            SessionRecord completed = MultisigFlowTest.runProtocol(
                    context, signers, retried);
            assertEquals(SessionState.COMPLETED, completed.state());
            assertTrue(context.aggregation().verifyAggregate(
                    msg, completed.aggregatePubHex(), completed.aggregateSignatureHex()));
        } finally {
            context.close();
        }
    }

    @Test
    void cancelledSessionIsNotRetryable(@TempDir Path tempDir) {
        Context context = startContext(tempDir);
        try {
            MultisigFlowTest.registerSigners(context, List.of("a", "b"));
            String msg = Hex.encode("cancel-msg".getBytes(StandardCharsets.UTF_8));
            context.sessionService().create("life-2", msg, List.of("a", "b"), null);

            SessionRecord cancelled = context.sessionService().cancel("life-2", "user abort");
            assertEquals(SessionState.FAILED_CANCELLED, cancelled.state());
            ServiceException ex = assertThrows(ServiceException.class,
                    () -> context.sessionService().retry("life-2"));
            assertEquals(ErrorCode.SESSION_NOT_RETRYABLE, ex.errorCode());
        } finally {
            context.close();
        }
    }

    @Test
    void incompleteAggregationIsNeverReturned(@TempDir Path tempDir) {
        Context context = startContext(tempDir);
        try {
            List<LocalSigner> signers = MultisigFlowTest.registerSigners(
                    context, List.of("a", "b"));
            String msg = Hex.encode("partial-msg".getBytes(StandardCharsets.UTF_8));
            SessionRecord session = context.sessionService()
                    .create("life-3", msg, List.of("a", "b"), null);
            String sessionId = session.sessionId();
            String salt = session.saltHex();
            context.sessionService().submitCommitment(sessionId, "a",
                    signers.get(0).commitment(sessionId, salt));
            context.sessionService().submitCommitment(sessionId, "b",
                    signers.get(1).commitment(sessionId, salt));
            String nonceA = signers.get(0).nonce(sessionId);
            String nonceB = signers.get(1).nonce(sessionId);
            context.sessionService().submitNonce(sessionId, "a", nonceA);
            context.sessionService().submitNonce(sessionId, "b", nonceB);

            String partialA = signers.get(0).partialSignature(
                    sessionId, msg,
                    signers.stream().map(LocalSigner::publicKeyHex).toList(),
                    List.of(nonceA, nonceB));
            context.sessionService().submitPartial(sessionId, "a", partialA);

            ServiceException ex = assertThrows(ServiceException.class,
                    () -> context.aggregation().aggregatePartials(sessionId));
            assertEquals(ErrorCode.SESSION_INCOMPLETE, ex.errorCode());
        } finally {
            context.close();
        }
    }
}
