package com.github.guoyyit.multisigaggregationjava.crypto;

import com.github.guoyyit.multisigaggregationjava.domain.NonceCommitment;
import com.github.guoyyit.multisigaggregationjava.domain.SigningView;

import java.math.BigInteger;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

/**
 * Client-side helper representing one signer that holds its own secret key.
 * It performs all signing locally; the aggregation service never receives
 * secret material.
 *
 * <p>Each nonce is generated for one session/round and is consumed at most once.
 * The class is not thread safe; one instance should be used per signer.
 */
public final class LocalSigner {

    private final BigInteger secretKey;
    private final Map<String, SecretNonces> nonces = new ConcurrentHashMap<>();
    private SecretNonces lastConsumed;

    public LocalSigner(BigInteger secretKey) {
        Schnorr.publicKeyFromSecret(secretKey);
        this.secretKey = secretKey;
    }

    public static LocalSigner generate() {
        return new LocalSigner(CurveP256.randomScalar());
    }

    public EcPoint publicKey() {
        return Schnorr.publicKeyFromSecret(secretKey);
    }

    /**
     * Generate a fresh two-nonce commitment for one session round. The secret
     * nonces are retained until consumed or discarded.
     */
    public NonceCommitment newCommitment(String sessionId, int round, boolean useSecondNonce) {
        BigInteger k1 = CurveP256.randomScalar();
        BigInteger k2 = useSecondNonce ? CurveP256.randomScalar() : null;
        SecretNonces secret = new SecretNonces(k1, k2);
        nonces.put(key(sessionId, round), secret);
        return new NonceCommitment("",
                CurveP256.mul(k1, CurveP256.generator()).encodeCompressedHex(),
                k2 == null ? null : CurveP256.mul(k2, CurveP256.generator()).encodeCompressedHex());
    }

    /** Produce the partial signature and consume the round's secret nonces. */
    public BigInteger signPartial(SigningView view) {
        SecretNonces secret = nonces.remove(key(view.sessionId(), view.round()));
        if (secret == null) {
            throw new IllegalStateException("no fresh nonce available for this session/round (already consumed?)");
        }
        BigInteger s = computePartial(view, secret);
        lastConsumed = secret;
        return s;
    }

    /**
     * Test-only: sign another view using nonces that were already consumed,
     * simulating nonce reuse across messages.
     */
    public BigInteger signPartialReusingLastNonce(SigningView view) {
        if (lastConsumed == null) {
            throw new IllegalStateException("no consumed nonce to replay");
        }
        return computePartial(view, lastConsumed);
    }

    /** Standard single-signer Schnorr signature, used for proof of possession. */
    public Schnorr.StandardSignature signStandard(byte[] message) {
        return Schnorr.signStandard(message, secretKey, CurveP256.randomScalar());
    }

    /**
     * Test-only escape hatch: reuse an already consumed nonce to demonstrate that
     * the server rejects reuse. Never use in real signing code paths.
     */
    public NonceCommitment replayLastCommitment() {
        if (lastConsumed == null) {
            throw new IllegalStateException("no commitment to replay");
        }
        return new NonceCommitment("",
                CurveP256.mul(lastConsumed.k1(), CurveP256.generator()).encodeCompressedHex(),
                lastConsumed.k2() == null ? null
                        : CurveP256.mul(lastConsumed.k2(), CurveP256.generator()).encodeCompressedHex());
    }

    private BigInteger computePartial(SigningView view, SecretNonces secret) {
        String ownKey = publicKey().encodeCompressedHex();
        int index = view.publicKeysHex().indexOf(ownKey);
        if (index < 0) {
            throw new IllegalStateException("signer is not a session participant");
        }
        BigInteger coefficient = Schnorr.keyAggregationCoefficient(decodeAll(view.publicKeysHex()), index);
        BigInteger e = new BigInteger(view.eHex(), 16);
        BigInteger b = new BigInteger(view.bHex(), 16);
        return Schnorr.partialSignature(secretKey, secret.k1(), secret.k2(), coefficient, b, e);
    }

    private static java.util.List<EcPoint> decodeAll(java.util.List<String> hexPoints) {
        java.util.List<EcPoint> points = new java.util.ArrayList<>(hexPoints.size());
        for (String hex : hexPoints) {
            points.add(EcPoint.decodeCompressedHex(hex));
        }
        return points;
    }

    private static String key(String sessionId, int round) {
        return sessionId + "#" + round;
    }

    private record SecretNonces(BigInteger k1, BigInteger k2) {
    }
}
