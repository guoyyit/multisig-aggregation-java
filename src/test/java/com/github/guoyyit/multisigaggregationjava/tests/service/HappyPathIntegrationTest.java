package com.github.guoyyit.multisigaggregationjava.tests.service;

import com.github.guoyyit.multisigaggregationjava.domain.AggregateSignature;
import com.github.guoyyit.multisigaggregationjava.domain.NonceCommitment;
import com.github.guoyyit.multisigaggregationjava.domain.PartialSignature;
import com.github.guoyyit.multisigaggregationjava.domain.SessionStatus;
import com.github.guoyyit.multisigaggregationjava.domain.SignSession;
import com.github.guoyyit.multisigaggregationjava.domain.SigningView;
import com.github.guoyyit.multisigaggregationjava.domain.VerificationResult;
import com.github.guoyyit.multisigaggregationjava.tests.support.TestHarness;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** End-to-end happy path through the service API. */
class HappyPathIntegrationTest {

    @TempDir
    Path tempDir;

    @Test
    void twoSignersAggregateAndVerify() {
        TestHarness harness = new TestHarness(tempDir.resolve("state.json"));
        harness.registerSigner("alice");
        harness.registerSigner("bob");
        harness.createSession("s1", "pay 10", List.of("bob", "alice"));
        harness.commitAll("s1", List.of("alice", "bob"));
        AggregateSignature signature = harness.completeSession("s1", List.of("alice", "bob"));

        assertNotNull(signature);
        assertEquals(SessionStatus.COMPLETED, harness.signingService.getSession("s1").getStatus());
        assertTrue(harness.signingService.verify("s1").valid());
    }

    @Test
    void aggregateVerificationEqualsVerifyingEveryPartial() {
        TestHarness harness = new TestHarness(tempDir.resolve("state.json"));
        harness.registerSigner("alice");
        harness.registerSigner("bob");
        harness.registerSigner("carol");
        harness.createSession("s2", "triple", List.of("alice", "bob", "carol"));
        harness.commitAll("s2", List.of("alice", "bob", "carol"));

        SigningView view = harness.signingService.signingView("s2");
        SignSession session = harness.signingService.getSession("s2");
        Map<String, NonceCommitment> commitments = new LinkedHashMap<>(session.getCommitments());
        Map<String, BigInteger> partials = new LinkedHashMap<>();
        for (String keyId : List.of("alice", "bob", "carol")) {
            partials.put(keyId, harness.signers.get(keyId).signPartial(view));
        }
        assertEquals(List.of(true, true, true),
                harness.verifyAllPartialsIndividually(view, commitments, partials));

        AggregateSignature aggregate = null;
        for (String keyId : List.of("alice", "bob", "carol")) {
            aggregate = harness.signingService.submitPartial("s2",
                    new PartialSignature(keyId, TestHarness.to32Hex(partials.get(keyId))));
        }
        assertNotNull(aggregate);
        assertTrue(harness.signingService.verify("s2").valid());
    }

    @Test
    void singleSignerSessionProducesStandardSchnorrSignature() {
        TestHarness harness = new TestHarness(tempDir.resolve("state.json"));
        harness.registerSigner("solo");
        harness.createSession("solo-session", "alone", List.of("solo"));
        harness.commitAll("solo-session", List.of("solo"));
        AggregateSignature signature = harness.completeSession("solo-session", List.of("solo"));

        assertEquals(harness.signers.get("solo").publicKey().encodeCompressedHex(),
                signature.aggregateKeyHex());
        VerificationResult result = harness.signingService.verifyStandalone(signature.messageHex(),
                signature.aggregateKeyHex(), signature.rHex(), signature.sHex());
        assertTrue(result.valid(), result.reason());
    }
}
