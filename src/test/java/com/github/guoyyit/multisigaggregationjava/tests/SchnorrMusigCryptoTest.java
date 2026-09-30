package com.github.guoyyit.multisigaggregationjava.tests;

import com.github.guoyyit.multisigaggregationjava.core.Hex;
import com.github.guoyyit.multisigaggregationjava.core.Musig;
import com.github.guoyyit.multisigaggregationjava.core.Schnorr;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SchnorrMusigCryptoTest {

    private final SecureRandom random = new SecureRandom();

    @Test
    void schnorrSignAndVerifyRoundTrips() {
        BigInteger secret = Schnorr.randomScalar(random);
        ECPoint publicKey = Schnorr.scalarBaseMult(secret);
        byte[] message = "hello multisig".getBytes(StandardCharsets.UTF_8);

        byte[] signature = Schnorr.signSchnorr(secret, message, random);

        assertTrue(Schnorr.verifySchnorr(publicKey, message, signature));
        byte[] tampered = "hello Multisig".getBytes(StandardCharsets.UTF_8);
        assertFalse(Schnorr.verifySchnorr(publicKey, tampered, signature));
    }

    @Test
    void proofOfPossessionVerifies() {
        BigInteger secret = Schnorr.randomScalar(random);
        ECPoint publicKey = Schnorr.scalarBaseMult(secret);
        byte[] proof = Schnorr.signPop(secret, Schnorr.compress(publicKey), random);

        assertTrue(Schnorr.verifyPop(publicKey, proof));
        BigInteger other = Schnorr.randomScalar(random);
        assertFalse(Schnorr.verifyPop(Schnorr.scalarBaseMult(other), proof));
    }

    @Test
    void singleSignerCoefficientIsOne() {
        BigInteger secret = Schnorr.randomScalar(random);
        ECPoint publicKey = Schnorr.scalarBaseMult(secret);
        List<ECPoint> singleton = Musig.sortPoints(List.of(publicKey));

        assertTrue(Musig.coefficient(singleton, publicKey).equals(BigInteger.ONE));
        assertTrue(Musig.aggregatePoint(singleton).equals(publicKey));
    }

    @Test
    void manualThreePartyMuSigAggregateVerifies() {
        int parties = 3;
        List<BigInteger> secrets = new ArrayList<>();
        List<ECPoint> publicKeys = new ArrayList<>();
        List<BigInteger> nonceScalars = new ArrayList<>();
        List<ECPoint> nonces = new ArrayList<>();
        for (int i = 0; i < parties; i++) {
            BigInteger x = Schnorr.randomScalar(random);
            secrets.add(x);
            publicKeys.add(Schnorr.scalarBaseMult(x));
            BigInteger k = Schnorr.randomScalar(random);
            nonceScalars.add(k);
            nonces.add(Schnorr.scalarBaseMult(k));
        }
        List<ECPoint> sorted = Musig.sortPoints(publicKeys);
        ECPoint aggregateKey = Musig.aggregatePoint(sorted);
        ECPoint nonceSum = Schnorr.sum(nonces.toArray(new ECPoint[0]));
        byte[] message = "aggregate me".getBytes(StandardCharsets.UTF_8);
        BigInteger e = Schnorr.challenge(nonceSum, aggregateKey, message);

        BigInteger sTotal = BigInteger.ZERO;
        for (int i = 0; i < parties; i++) {
            BigInteger a = Musig.coefficient(sorted, publicKeys.get(i));
            BigInteger sPart = nonceScalars.get(i)
                    .add(e.multiply(a).multiply(secrets.get(i)))
                    .mod(Schnorr.curveOrder());
            sTotal = sTotal.add(sPart);
        }
        sTotal = sTotal.mod(Schnorr.curveOrder());
        byte[] signature = Schnorr.encodeSignature(nonceSum, sTotal);

        assertTrue(Schnorr.verifySchnorr(aggregateKey, message, signature));
        assertTrue(Hex.encode(signature).length() == 130);
    }
}
