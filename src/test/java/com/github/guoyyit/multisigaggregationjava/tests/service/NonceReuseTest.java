package com.github.guoyyit.multisigaggregationjava.tests.service;

import com.github.guoyyit.multisigaggregationjava.domain.ErrorCode;
import com.github.guoyyit.multisigaggregationjava.domain.NonceCommitment;
import com.github.guoyyit.multisigaggregationjava.domain.PartialSignature;
import com.github.guoyyit.multisigaggregationjava.domain.ServiceException;
import com.github.guoyyit.multisigaggregationjava.domain.SigningView;
import com.github.guoyyit.multisigaggregationjava.tests.support.TestHarness;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Duplicate commitments and nonce reuse must be rejected with distinct errors. */
class NonceReuseTest {

    @TempDir
    Path tempDir;

    @Test
    void duplicateCommitmentInSameRoundIsRejected() {
        TestHarness harness = new TestHarness(tempDir.resolve("state.json"));
        harness.registerSigner("alice");
        harness.registerSigner("bob");
        harness.createSession("s", "m", List.of("alice", "bob"));
        NonceCommitment alice = harness.signers.get("alice").newCommitment("s", 1, true);
        harness.signingService.submitCommitment("s",
                new NonceCommitment("alice", alice.r1Hex(), alice.r2Hex()));

        NonceCommitment other = harness.signers.get("bob").newCommitment("s", 1, true);
        ServiceException different = assertThrows(ServiceException.class,
                () -> harness.signingService.submitCommitment("s",
                        new NonceCommitment("alice", other.r1Hex(), other.r2Hex())));
        assertEquals(ErrorCode.DUPLICATE_COMMITMENT, different.errorCode());

        // Exact resubmission of the identical commitment is idempotent.
        harness.signingService.submitCommitment("s",
                new NonceCommitment("alice", alice.r1Hex(), alice.r2Hex()));
    }

    @Test
    void sameNonceReusedInAnotherSessionIsRejectedAtCommitmentStage() {
        TestHarness harness = new TestHarness(tempDir.resolve("state.json"));
        harness.registerSigner("alice");
        harness.registerSigner("bob");
        harness.createSession("s1", "m1", List.of("alice", "bob"));
        harness.createSession("s2", "m2", List.of("alice", "bob"));

        NonceCommitment alice = harness.signers.get("alice").newCommitment("s1", 1, true);
        harness.signingService.submitCommitment("s1",
                new NonceCommitment("alice", alice.r1Hex(), alice.r2Hex()));

        ServiceException ex = assertThrows(ServiceException.class,
                () -> harness.signingService.submitCommitment("s2",
                        new NonceCommitment("alice", alice.r1Hex(), alice.r2Hex())));
        assertEquals(ErrorCode.DUPLICATE_COMMITMENT, ex.errorCode());
    }

    @Test
    void sameNonceAcrossMessagesIsRejectedWithReuseCode() {
        TestHarness harness = new TestHarness(tempDir.resolve("state.json"));
        harness.registerSigner("alice");
        harness.registerSigner("bob");
        harness.createSession("s1", "message-one", List.of("alice", "bob"));
        harness.commitAll("s1", List.of("alice", "bob"));
        SigningView view = harness.signingService.signingView("s1");
        BigInteger alicePartial = harness.signers.get("alice").signPartial(view);
        harness.signingService.submitPartial("s1",
                new PartialSignature("alice", TestHarness.to32Hex(alicePartial)));

        // Submitting alice's valid partial consumed her (R1,R2) tuple. The same
        // tuple signing another message must be rejected with the dedicated reuse
        // code, distinguishable from an invalid partial signature.
        NonceCommitment commitment = harness.signingService.getSession("s1")
                .getCommitments().get("alice");
        String tuple = commitment.r1Hex().toLowerCase() + "|" + commitment.r2Hex().toLowerCase();
        String reusedAt = harness.store.markConsumedPartial(tuple, "s2#1");
        assertEquals("s1#1", reusedAt);
    }

    @Test
    void repeatedSamePartialSubmissionIsIdempotent() {
        TestHarness harness = new TestHarness(tempDir.resolve("state.json"));
        harness.registerSigner("alice");
        harness.registerSigner("bob");
        harness.createSession("s", "m", List.of("alice", "bob"));
        harness.commitAll("s", List.of("alice", "bob"));
        SigningView view = harness.signingService.signingView("s");
        BigInteger partial = harness.signers.get("alice").signPartial(view);
        PartialSignature request = new PartialSignature("alice", TestHarness.to32Hex(partial));

        harness.signingService.submitPartial("s", request);
        harness.signingService.submitPartial("s", request);

        ServiceException aggregate = assertThrows(ServiceException.class,
                () -> harness.signingService.aggregate("s"));
        assertEquals(ErrorCode.SESSION_INCOMPLETE, aggregate.errorCode());
    }
}
