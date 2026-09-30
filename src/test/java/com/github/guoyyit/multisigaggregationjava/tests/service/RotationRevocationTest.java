package com.github.guoyyit.multisigaggregationjava.tests.service;

import com.github.guoyyit.multisigaggregationjava.crypto.LocalSigner;
import com.github.guoyyit.multisigaggregationjava.domain.ErrorCode;
import com.github.guoyyit.multisigaggregationjava.domain.KeyStatus;
import com.github.guoyyit.multisigaggregationjava.domain.ServiceException;
import com.github.guoyyit.multisigaggregationjava.tests.support.TestHarness;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Key rotation and revocation semantics. */
class RotationRevocationTest {

    @TempDir
    Path tempDir;

    @Test
    void rotatedKeyIsUsedForNewSessionsAndOldKeyCannotParticipate() {
        TestHarness harness = new TestHarness(tempDir.resolve("state.json"));
        harness.registerSigner("alice");
        harness.registerSigner("bob");

        harness.createSession("before", "m1", List.of("alice", "bob"));
        harness.commitAll("before", List.of("alice", "bob"));
        var beforeSig = harness.completeSession("before", List.of("alice", "bob"));

        LocalSigner newAlice = LocalSigner.generate();
        String oldKeyHex = harness.signers.get("alice").publicKey().encodeCompressedHex();
        harness.signers.put("alice2", newAlice);
        byte[] popMessage = TestHarness.proofMessage("alice2",
                newAlice.publicKey().encodeCompressedHex());
        var pop = newAlice.signStandard(popMessage);
        harness.keyService.rotate("alice", "alice2", newAlice.publicKey().encodeCompressedHex(),
                pop.r().encodeCompressedHex() + TestHarness.to32Hex(pop.s()),
                TestHarness.toHex(popMessage));

        assertEquals(KeyStatus.REVOKED, harness.keyService.get("alice").status());
        assertEquals(KeyStatus.ACTIVE, harness.keyService.get("alice2").status());

        ServiceException oldParticipates = assertThrows(ServiceException.class,
                () -> harness.createSession("bad", "m2", List.of("alice", "bob")));
        assertEquals(ErrorCode.KEY_REVOKED, oldParticipates.errorCode());

        harness.createSession("after", "m2", List.of("alice2", "bob"));
        harness.commitAll("after", List.of("alice2", "bob"));
        var afterSig = harness.completeSession("after", List.of("alice2", "bob"));
        assertTrue(harness.signingService.verify("after").valid());
        assertNotEquals(beforeSig.aggregateKeyHex(), afterSig.aggregateKeyHex());
        assertNotNull(oldKeyHex);
    }

    @Test
    void revokedKeyCannotJoinNewSessions() {
        TestHarness harness = new TestHarness(tempDir.resolve("state.json"));
        harness.registerSigner("alice");
        harness.keyService.revoke("alice", "compromised device");

        ServiceException ex = assertThrows(ServiceException.class,
                () -> harness.createSession("s", "m", List.of("alice")));
        assertEquals(ErrorCode.KEY_REVOKED, ex.errorCode());

        // Revocation is idempotent.
        assertEquals(KeyStatus.REVOKED, harness.keyService.revoke("alice", "again").status());
    }

    @Test
    void revocationIsAuditableAndHistoryStillVerifies() {
        TestHarness harness = new TestHarness(tempDir.resolve("state.json"));
        harness.registerSigner("alice");
        harness.registerSigner("bob");
        harness.createSession("historical", "m", List.of("alice", "bob"));
        harness.commitAll("historical", List.of("alice", "bob"));
        harness.completeSession("historical", List.of("alice", "bob"));

        harness.keyService.revoke("bob", "off-boarded");
        var revoked = harness.keyService.get("bob");
        assertEquals("off-boarded", revoked.revokedReason());
        assertNotNull(revoked.revokedAt());
        // The revoked public key is retained and the old aggregate still verifies.
        assertTrue(harness.signingService.verify("historical").valid());
        assertTrue(harness.signingService.verifyStandalone(
                harness.signingService.getSession("historical").getAggregateSignature().messageHex(),
                harness.signingService.getSession("historical").getAggregateSignature().aggregateKeyHex(),
                harness.signingService.getSession("historical").getAggregateSignature().rHex(),
                harness.signingService.getSession("historical").getAggregateSignature().sHex()).valid());
    }
}
