package com.github.guoyyit.multisigaggregationjava.tests.security;

import com.github.guoyyit.multisigaggregationjava.crypto.CurveP256;
import com.github.guoyyit.multisigaggregationjava.crypto.EcPoint;
import com.github.guoyyit.multisigaggregationjava.crypto.LocalSigner;
import com.github.guoyyit.multisigaggregationjava.crypto.Schnorr;
import com.github.guoyyit.multisigaggregationjava.domain.ErrorCode;
import com.github.guoyyit.multisigaggregationjava.domain.ServiceException;
import com.github.guoyyit.multisigaggregationjava.tests.support.TestHarness;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Rogue-key and related-key attacks must not yield forgeries. */
class MaliciousPublicKeyTest {

    @TempDir
    Path tempDir;

    @Test
    void registrationWithoutValidProofOfPossessionIsRejected() {
        TestHarness harness = new TestHarness(tempDir.resolve("state.json"));
        LocalSigner attacker = LocalSigner.generate();
        String publicKeyHex = attacker.publicKey().encodeCompressedHex();
        byte[] popMessage = TestHarness.proofMessage("attacker", publicKeyHex);
        Schnorr.StandardSignature pop = attacker.signStandard(popMessage);
        String validPopSig = pop.r().encodeCompressedHex() + TestHarness.to32Hex(pop.s());

        ServiceException missing = assertThrows(ServiceException.class,
                () -> harness.keyService.register("attacker", publicKeyHex, null,
                        TestHarness.toHex(popMessage)));
        assertEquals(ErrorCode.INVALID_PROOF_OF_POSSESSION, missing.errorCode());

        byte[] wrongMessage = TestHarness.proofMessage("victim", publicKeyHex);
        ServiceException wrong = assertThrows(ServiceException.class,
                () -> harness.keyService.register("attacker", publicKeyHex, validPopSig,
                        TestHarness.toHex(wrongMessage)));
        assertEquals(ErrorCode.INVALID_PROOF_OF_POSSESSION, wrong.errorCode());

        String tamperedS = pop.r().encodeCompressedHex()
                + TestHarness.to32Hex(pop.s().add(BigInteger.ONE).mod(CurveP256.N));
        ServiceException tampered = assertThrows(ServiceException.class,
                () -> harness.keyService.register("attacker", publicKeyHex, tamperedS,
                        TestHarness.toHex(popMessage)));
        assertEquals(ErrorCode.INVALID_PROOF_OF_POSSESSION, tampered.errorCode());
    }

    @Test
    void rogueKeyAttackCannotForgeAggregateSignature() {
        TestHarness harness = new TestHarness(tempDir.resolve("state.json"));
        LocalSigner victim = LocalSigner.generate();
        harness.registerSigner("victim", victim);

        // Classic rogue-key construction: X_att = a_v*X_v + a_a*R - e... here the
        // attacker attempts X_attacker = R - a_v*X_v so that Xagg = R would let a
        // zero-knowledge forgery pass. The attacker cannot produce a proof of
        // possession for X_attacker because it does not know its discrete log.
        byte[] message = "forged".getBytes(StandardCharsets.UTF_8);
        List<EcPoint> trialKeys = List.of(victim.publicKey());
        EcPoint victimScaled = CurveP256.mul(Schnorr.keyAggregationCoefficient(
                expand(victim.publicKey()), 0), victim.publicKey());

        BigInteger k = CurveP256.randomScalar();
        EcPoint r = CurveP256.mul(k, CurveP256.generator());
        EcPoint roguePublic = CurveP256.add(r, CurveP256.neg(victimScaled));
        CurveP256.requireOnCurve(roguePublic);

        // Even if registration were bypassed, evaluate the aggregate key under the
        // real coefficients and show the naive forgery s = k does not verify.
        List<EcPoint> withRogue = java.util.stream.Stream.of(victim.publicKey(), roguePublic)
                .sorted(java.util.Comparator.comparing(EcPoint::encodeCompressedHex))
                .toList();
        EcPoint aggregateKey = Schnorr.aggregatePublicKey(withRogue);
        BigInteger e = Schnorr.challenge(r, aggregateKey, message);
        assertFalse(Schnorr.verifyAggregate(message, aggregateKey, r, k));
        assertTrue(e.signum() > 0);

        // Registration of the rogue key without a valid PoP is refused.
        byte[] popMessage = TestHarness.proofMessage("attacker", roguePublic.encodeCompressedHex());
        String forgedPop = r.encodeCompressedHex() + TestHarness.to32Hex(k);
        ServiceException ex = assertThrows(ServiceException.class,
                () -> harness.keyService.register("attacker", roguePublic.encodeCompressedHex(),
                        forgedPop, TestHarness.toHex(popMessage)));
        assertEquals(ErrorCode.INVALID_PROOF_OF_POSSESSION, ex.errorCode());
    }

    @Test
    void relatedKeySubstitutionIsRejected() {
        TestHarness harness = new TestHarness(tempDir.resolve("state.json"));
        LocalSigner victim = LocalSigner.generate();
        harness.registerSigner("victim", victim);

        // Attacker registers -X_v (same discrete log knowledge needed) with its own
        // valid PoP, then tries to sign a session as victim; server must require a
        // participant proof matching the exact registered key.
        BigInteger minusOne = CurveP256.N.subtract(BigInteger.ONE);
        EcPoint negated = CurveP256.mul(minusOne, victim.publicKey());
        LocalSigner attackerHoldingNegLog = new LocalSigner(CurveP256.N.subtract(victimSecret(victim)));
        harness.registerSigner("attacker", attackerHoldingNegLog);
        assertEquals(negated, attackerHoldingNegLog.publicKey());

        harness.createSession("s", "msg", List.of("victim"));
        harness.commitAll("s", List.of("victim"));
        var view = harness.signingService.signingView("s");
        // A scalar produced with the related (-x) key and a fresh attacker nonce
        // cannot satisfy the victim public key verification equation.
        BigInteger attackerNonce = CurveP256.randomScalar();
        BigInteger e = new BigInteger(1, TestHarness.fromHex(view.eHex()));
        BigInteger attackerSecret = CurveP256.N.subtract(victimSecret(victim));
        BigInteger wrongPartial = attackerNonce.add(e.multiply(attackerSecret))
                .mod(CurveP256.N);
        ServiceException ex = assertThrows(ServiceException.class, () ->
                harness.signingService.submitPartial("s",
                        new com.github.guoyyit.multisigaggregationjava.domain.PartialSignature(
                                "victim", TestHarness.to32Hex(wrongPartial))));
        assertEquals(ErrorCode.INVALID_PARTIAL_SIGNATURE, ex.errorCode());
    }

    private static List<EcPoint> expand(EcPoint victim) {
        return List.of(victim);
    }

    private static BigInteger victimSecret(LocalSigner signer) {
        try {
            var field = LocalSigner.class.getDeclaredField("secretKey");
            field.setAccessible(true);
            return (BigInteger) field.get(signer);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }
}
