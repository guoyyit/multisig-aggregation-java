package com.github.guoyyit.multisigaggregationjava.tests.service;

import com.github.guoyyit.multisigaggregationjava.domain.ErrorCode;
import com.github.guoyyit.multisigaggregationjava.domain.FailureReason;
import com.github.guoyyit.multisigaggregationjava.domain.NonceCommitment;
import com.github.guoyyit.multisigaggregationjava.domain.ServiceException;
import com.github.guoyyit.multisigaggregationjava.domain.SessionStatus;
import com.github.guoyyit.multisigaggregationjava.tests.support.TestHarness;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Persistence and restart recovery behavior. */
class CrashRecoveryTest {

    @TempDir
    Path tempDir;

    @Test
    void registrationsSurviveRestart() {
        Path stateFile = tempDir.resolve("state.json");
        TestHarness first = new TestHarness(stateFile);
        first.registerSigner("alice");
        first.registerSigner("bob");

        TestHarness reopened = new TestHarness(stateFile);
        assertNotNull(reopened.keyService.get("alice"));
        assertNotNull(reopened.keyService.get("bob"));
    }

    @Test
    void inFlightSessionIsFailedAfterRestartAndRetryUsesFreshNonces() {
        Path stateFile = tempDir.resolve("state.json");
        TestHarness first = new TestHarness(stateFile);
        first.registerSigner("alice");
        first.registerSigner("bob");
        first.createSession("inflight", "m", List.of("alice", "bob"));
        first.commitAll("inflight", List.of("alice", "bob"));

        // Simulate a restart: brand-new services from the same state file.
        TestHarness reopened = new TestHarness(stateFile);
        reopened.signers.putAll(first.signers);
        List<String> failed = reopened.recoveryService(true).recoverOnStartup(reopened.now());
        assertEquals(List.of("inflight"), failed);
        var session = reopened.signingService.getSession("inflight");
        assertEquals(SessionStatus.FAILED, session.getStatus());
        assertEquals(FailureReason.RESTART_RECOVERY, session.getFailureReason());
        assertTrue(session.isRecoveredAfterRestart());

        // Old commitment cannot be presented again: retry bumps to a new round.
        var oldAlice = first.signingService.getSession("inflight").getCommitments().get("alice");
        reopened.signingService.retry("inflight");
        ServiceException reused = assertThrows(ServiceException.class,
                () -> reopened.signingService.submitCommitment("inflight",
                        new NonceCommitment("alice", oldAlice.r1Hex(), oldAlice.r2Hex())));
        assertEquals(ErrorCode.DUPLICATE_COMMITMENT, reused.errorCode());

        reopened.commitAll("inflight", List.of("alice", "bob"));
        var signature = reopened.completeSession("inflight", List.of("alice", "bob"));
        assertEquals(2, signature.round());
        assertTrue(reopened.signingService.verify("inflight").valid());
    }

    @Test
    void completedSessionStillVerifiesAfterRestart() {
        Path stateFile = tempDir.resolve("state.json");
        TestHarness first = new TestHarness(stateFile);
        first.registerSigner("alice");
        first.registerSigner("bob");
        first.createSession("done", "m", List.of("alice", "bob"));
        first.commitAll("done", List.of("alice", "bob"));
        first.completeSession("done", List.of("alice", "bob"));

        TestHarness reopened = new TestHarness(stateFile);
        reopened.recoveryService(true).recoverOnStartup(reopened.now());
        assertEquals(SessionStatus.COMPLETED, reopened.signingService.getSession("done").getStatus());
        assertTrue(reopened.signingService.verify("done").valid());
    }

    @Test
    void noncesAreNotReusedAcrossRestart() {
        Path stateFile = tempDir.resolve("state.json");
        TestHarness first = new TestHarness(stateFile);
        first.registerSigner("alice");
        first.registerSigner("bob");
        first.createSession("s1", "m1", List.of("alice", "bob"));
        var commitment = first.signers.get("alice").newCommitment("s1", 1, true);
        first.signingService.submitCommitment("s1",
                new NonceCommitment("alice", commitment.r1Hex(), commitment.r2Hex()));

        TestHarness reopened = new TestHarness(stateFile);
        reopened.signers.putAll(first.signers);
        reopened.recoveryService(true).recoverOnStartup(reopened.now());
        reopened.createSession("s2", "m2", List.of("alice", "bob"));
        ServiceException ex = assertThrows(ServiceException.class,
                () -> reopened.signingService.submitCommitment("s2",
                        new NonceCommitment("alice", commitment.r1Hex(), commitment.r2Hex())));
        assertEquals(ErrorCode.DUPLICATE_COMMITMENT, ex.errorCode());
    }
}
