package com.github.guoyyit.multisigaggregationjava.tests.service;

import com.github.guoyyit.multisigaggregationjava.domain.ErrorCode;
import com.github.guoyyit.multisigaggregationjava.domain.FailureReason;
import com.github.guoyyit.multisigaggregationjava.domain.PartialSignature;
import com.github.guoyyit.multisigaggregationjava.domain.ServiceException;
import com.github.guoyyit.multisigaggregationjava.domain.SessionStatus;
import com.github.guoyyit.multisigaggregationjava.domain.SignSession;
import com.github.guoyyit.multisigaggregationjava.domain.SigningView;
import com.github.guoyyit.multisigaggregationjava.tests.support.TestHarness;
import com.github.guoyyit.multisigaggregationjava.tests.support.TestHarness.MutableClock;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Offline participants, timeout, invalid submissions, retry and cancel. */
class OfflineAndTimeoutTest {

    @TempDir
    Path tempDir;

    @Test
    void timedOutSessionBecomesFailedRetryableWithoutPartialAggregate() {
        MutableClock clock = new MutableClock();
        TestHarness harness = new TestHarness(tempDir.resolve("state.json"), clock, 1000L);
        harness.registerSigner("alice");
        harness.registerSigner("bob");
        harness.createSession("s", "m", List.of("alice", "bob"));
        harness.commitAll("s", List.of("alice", "bob"));

        // Only alice signs; bob stays offline.
        SigningView view = harness.signingService.signingView("s");
        BigInteger alicePartial = harness.signers.get("alice").signPartial(view);
        harness.signingService.submitPartial("s",
                new PartialSignature("alice", TestHarness.to32Hex(alicePartial)));

        clock.advance(1001L);
        List<String> expired = harness.signingService.sweepTimeouts(clock.millis());
        assertEquals(List.of("s"), expired);
        SignSession session = harness.signingService.getSession("s");
        assertEquals(SessionStatus.FAILED, session.getStatus());
        assertEquals(FailureReason.TIMEOUT, session.getFailureReason());
        assertNull(session.getAggregateSignature());

        ServiceException aggregate = assertThrows(ServiceException.class,
                () -> harness.signingService.aggregate("s"));
        assertEquals(ErrorCode.SESSION_INCOMPLETE, aggregate.errorCode());
    }

    @Test
    void invalidPartialFailsAndRetryStartsFreshRound() {
        TestHarness harness = new TestHarness(tempDir.resolve("state.json"));
        harness.registerSigner("alice");
        harness.registerSigner("bob");
        harness.createSession("s", "m", List.of("alice", "bob"));
        harness.commitAll("s", List.of("alice", "bob"));
        harness.signingService.signingView("s");

        for (int attempt = 1; attempt <= 3; attempt++) {
            int captured = attempt;
            ServiceException invalid = assertThrows(ServiceException.class,
                    () -> harness.signingService.submitPartial("s",
                            new PartialSignature("alice",
                                    TestHarness.to32Hex(BigInteger.valueOf(captured)))));
            assertEquals(ErrorCode.INVALID_PARTIAL_SIGNATURE, invalid.errorCode());
        }
        assertEquals(SessionStatus.FAILED, harness.signingService.getSession("s").getStatus());
        assertEquals(FailureReason.INVALID_SUBMISSION,
                harness.signingService.getSession("s").getFailureReason());

        SignSession retried = harness.signingService.retry("s");
        assertEquals(SessionStatus.OPEN, retried.getStatus());
        assertEquals(2, retried.getRound());
        assertTrue(retried.getCommitments().isEmpty());
        assertTrue(retried.getPartials().isEmpty());

        // Fresh round completes successfully.
        harness.commitAll("s", List.of("alice", "bob"));
        var signature = harness.completeSession("s", List.of("alice", "bob"));
        assertEquals(2, signature.round());
        assertTrue(harness.signingService.verify("s").valid());
    }

    @Test
    void cancelIsDeterministicAndBlocksFurtherSubmission() {
        TestHarness harness = new TestHarness(tempDir.resolve("state.json"));
        harness.registerSigner("alice");
        harness.registerSigner("bob");
        harness.createSession("s", "m", List.of("alice", "bob"));

        harness.signingService.cancel("s", "abort");
        SignSession cancelled = harness.signingService.cancel("s", "abort");
        assertEquals(SessionStatus.CANCELLED, cancelled.getStatus());

        ServiceException commit = assertThrows(ServiceException.class,
                () -> harness.commitAll("s", List.of("alice", "bob")));
        assertEquals(ErrorCode.SESSION_NOT_OPEN, commit.errorCode());

        ServiceException retry = assertThrows(ServiceException.class,
                () -> harness.signingService.retry("s"));
        assertEquals(ErrorCode.SESSION_NOT_RETRYABLE, retry.errorCode());
    }

    @Test
    void aggregateBeforeAllPartialsIsRejected() {
        TestHarness harness = new TestHarness(tempDir.resolve("state.json"));
        harness.registerSigner("alice");
        harness.registerSigner("bob");
        harness.createSession("s", "m", List.of("alice", "bob"));
        harness.commitAll("s", List.of("alice", "bob"));
        SigningView view = harness.signingService.signingView("s");
        BigInteger partial = harness.signers.get("alice").signPartial(view);
        harness.signingService.submitPartial("s",
                new PartialSignature("alice", TestHarness.to32Hex(partial)));

        ServiceException ex = assertThrows(ServiceException.class,
                () -> harness.signingService.aggregate("s"));
        assertEquals(ErrorCode.SESSION_INCOMPLETE, ex.errorCode());
    }
}
