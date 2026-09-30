package com.github.guoyyit.multisigaggregationjava.tests.service;

import com.github.guoyyit.multisigaggregationjava.domain.KeyStatus;
import com.github.guoyyit.multisigaggregationjava.domain.NonceCommitment;
import com.github.guoyyit.multisigaggregationjava.domain.PartialSignature;
import com.github.guoyyit.multisigaggregationjava.domain.SessionStatus;
import com.github.guoyyit.multisigaggregationjava.domain.SigningView;
import com.github.guoyyit.multisigaggregationjava.tests.support.TestHarness;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Deterministic behavior under concurrent sessions, registrations and revoke. */
class ConcurrencyTest {

    @TempDir
    Path tempDir;

    @Test
    void concurrentSessionsCompleteWithDeterministicResult() throws Exception {
        TestHarness harness = new TestHarness(tempDir.resolve("state.json"));
        harness.registerSigner("alice");
        harness.registerSigner("bob");

        int sessions = 12;
        ExecutorService pool = Executors.newFixedThreadPool(6);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<Throwable> failures = new ConcurrentLinkedQueue<>();
        for (int i = 0; i < sessions; i++) {
            String sessionId = "session-" + i;
            String message = "message-" + i;
            pool.submit(() -> {
                try {
                    start.await();
                    List<String> participants = List.of("alice", "bob");
                    harness.createSession(sessionId, message, participants);
                    harness.commitAll(sessionId, participants);
                    SigningView view = harness.signingService.signingView(sessionId);
                    for (String keyId : participants) {
                        BigInteger partial = harness.signers.get(keyId).signPartial(view);
                        harness.signingService.submitPartial(sessionId,
                                new PartialSignature(keyId, TestHarness.to32Hex(partial)));
                    }
                } catch (Throwable t) {
                    failures.add(t);
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS));
        assertTrue(failures.isEmpty(), () -> failures.toString());

        for (int i = 0; i < sessions; i++) {
            String sessionId = "session-" + i;
            assertEquals(SessionStatus.COMPLETED,
                    harness.signingService.getSession(sessionId).getStatus());
            assertTrue(harness.signingService.verify(sessionId).valid());
        }
    }

    @Test
    void concurrentRegisterAndRevokeDoNotOverwrite() throws Exception {
        // Each thread owns a distinct key id; concurrent registrations and an
        // interleaved revocation of one key must both land durably with no loss.
        TestHarness harness = new TestHarness(tempDir.resolve("state.json"));
        int count = 16;
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        for (int i = 0; i < count; i++) {
            final int index = i;
            pool.submit(() -> {
                try {
                    start.await();
                    harness.registerSigner("key-" + index);
                    if (index % 4 == 0) {
                        harness.keyService.revoke("key-" + index, "concurrent revoke");
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS));

        for (int i = 0; i < count; i++) {
            KeyStatus expected = i % 4 == 0 ? KeyStatus.REVOKED : KeyStatus.ACTIVE;
            assertEquals(expected, harness.keyService.get("key-" + i).status(),
                    "key-" + i + " final status lost under concurrency");
        }

        // Reopen state from disk: durable outcome matches in-memory outcome.
        TestHarness reopened = new TestHarness(tempDir.resolve("state.json"));
        assertEquals(KeyStatus.REVOKED, reopened.keyService.get("key-0").status());
        assertEquals(KeyStatus.ACTIVE, reopened.keyService.get("key-1").status());
    }
}
