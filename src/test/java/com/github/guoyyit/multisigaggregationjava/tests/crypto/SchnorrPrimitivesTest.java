package com.github.guoyyit.multisigaggregationjava.tests.crypto;

import com.github.guoyyit.multisigaggregationjava.crypto.CurveP256;
import com.github.guoyyit.multisigaggregationjava.crypto.EcPoint;
import com.github.guoyyit.multisigaggregationjava.crypto.Schnorr;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Tests for P-256 Schnorr and MuSig2 primitives. */
class SchnorrPrimitivesTest {

    @Test
    void standardSchnorrSignAndVerify() {
        BigInteger sk = CurveP256.randomScalar();
        EcPoint pk = Schnorr.publicKeyFromSecret(sk);
        byte[] message = "hello multisig".getBytes(StandardCharsets.UTF_8);
        Schnorr.StandardSignature signature = Schnorr.signStandard(message, sk, CurveP256.randomScalar());
        assertTrue(Schnorr.verifyStandard(message, pk, signature.r(), signature.s()));
        assertFalse(Schnorr.verifyStandard("other message".getBytes(StandardCharsets.UTF_8),
                pk, signature.r(), signature.s()));
    }

    @Test
    void tamperedSignatureIsRejected() {
        BigInteger sk = CurveP256.randomScalar();
        EcPoint pk = Schnorr.publicKeyFromSecret(sk);
        byte[] message = "m".getBytes(StandardCharsets.UTF_8);
        Schnorr.StandardSignature signature = Schnorr.signStandard(message, sk, CurveP256.randomScalar());
        BigInteger tamperedS = signature.s().add(BigInteger.ONE).mod(CurveP256.N);
        assertFalse(Schnorr.verifyStandard(message, pk, signature.r(), tamperedS));
    }

    @Test
    void aggregateKeyAndAggregateSignatureVerifyForMultipleSigners() {
        int n = 3;
        record Signer(BigInteger sk, EcPoint pk) {
        }
        List<Signer> signers = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            BigInteger sk = CurveP256.randomScalar();
            signers.add(new Signer(sk, Schnorr.publicKeyFromSecret(sk)));
        }
        signers.sort(Comparator.comparing(signer -> signer.pk().encodeCompressedHex()));
        List<EcPoint> publicKeys = new ArrayList<>(signers.stream().map(Signer::pk).toList());
        List<BigInteger> coefficients = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            coefficients.add(Schnorr.keyAggregationCoefficient(publicKeys, i));
        }
        EcPoint aggregateKey = Schnorr.aggregatePublicKey(publicKeys);

        byte[] message = "aggregate me".getBytes(StandardCharsets.UTF_8);
        List<Schnorr.NoncePair> pairs = new ArrayList<>();
        List<BigInteger> k1s = new ArrayList<>();
        List<BigInteger> k2s = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            BigInteger k1 = CurveP256.randomScalar();
            BigInteger k2 = CurveP256.randomScalar();
            k1s.add(k1);
            k2s.add(k2);
            pairs.add(new Schnorr.NoncePair(
                    CurveP256.mul(k1, CurveP256.generator()),
                    CurveP256.mul(k2, CurveP256.generator())));
        }
        Schnorr.AggregateNonce aggregateNonce = Schnorr.aggregateNonce(pairs, aggregateKey, message);
        BigInteger e = Schnorr.challenge(aggregateNonce.r(), aggregateKey, message);

        List<BigInteger> partials = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            BigInteger sI = Schnorr.partialSignature(signers.get(i).sk(),
                    k1s.get(i), k2s.get(i), coefficients.get(i), aggregateNonce.b(), e);
            partials.add(sI);
        }
        for (int i = 0; i < n; i++) {
            assertTrue(Schnorr.verifyPartial(pairs.get(i).r1(), pairs.get(i).r2(), publicKeys.get(i),
                    partials.get(i), coefficients.get(i), aggregateNonce.b(), e));
        }
        BigInteger s = Schnorr.sumPartials(partials);
        assertTrue(Schnorr.verifyAggregate(message, aggregateKey, aggregateNonce.r(), s));
    }

    @Test
    void singleSignerCollapsesToStandardSchnorr() {
        BigInteger sk = CurveP256.randomScalar();
        EcPoint pk = Schnorr.publicKeyFromSecret(sk);
        List<EcPoint> single = List.of(pk);
        assertEquals(BigInteger.ONE, Schnorr.keyAggregationCoefficient(single, 0));
        assertEquals(pk, Schnorr.aggregatePublicKey(single));

        byte[] message = "solo".getBytes(StandardCharsets.UTF_8);
        BigInteger k = CurveP256.randomScalar();
        EcPoint r = CurveP256.mul(k, CurveP256.generator());
        Schnorr.AggregateNonce nonce = Schnorr.aggregateNonce(
                List.of(new Schnorr.NoncePair(r, null)), pk, message);
        assertEquals(BigInteger.ZERO, nonce.b());
        BigInteger e = Schnorr.challenge(nonce.r(), pk, message);
        BigInteger s = Schnorr.partialSignature(sk, k, null, BigInteger.ONE, BigInteger.ZERO, e);
        assertTrue(Schnorr.verifyAggregate(message, pk, nonce.r(), s));
        assertTrue(Schnorr.verifyStandard(message, pk, nonce.r(), s));
    }

    @Test
    void invalidCurvePointIsRejected() {
        String validX = Schnorr.publicKeyFromSecret(CurveP256.randomScalar()).encodeCompressedHex().substring(2);
        String offCurveUncompressed = "04" + validX + "01".repeat(32);
        assertThrows(IllegalArgumentException.class,
                () -> EcPoint.decodeCompressedHex(offCurveUncompressed));
    }

}
