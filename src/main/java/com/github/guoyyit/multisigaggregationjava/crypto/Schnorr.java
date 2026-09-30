package com.github.guoyyit.multisigaggregationjava.crypto;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * Pure, stateless Schnorr/MuSig2 primitives over P-256 with SHA-256.
 *
 * <p>Conventions:
 * <ul>
 *   <li>challenge e = H(R || X || m) using tagged hash "SchnorrSign/v1";</li>
 *   <li>MuSig2 key coefficient a_i = H_tag("KeyAgg/v1", L || X_i) where L is the
 *       hash of the canonical lexicographically sorted participant key list;</li>
 *   <li>single participant sessions collapse to plain Schnorr (a = 1, b = 0) so
 *       the aggregate signature is a standard Schnorr signature.</li>
 * </ul>
 */
public final class Schnorr {

    private Schnorr() {
    }

    public static byte[] taggedHash(String tag, byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] tagHash = digest.digest(tag.getBytes(StandardCharsets.UTF_8));
            digest.reset();
            digest.update(tagHash);
            digest.update(tagHash);
            digest.update(data);
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Standard Schnorr signature of message m: returns (R, s) with s = k + e*x. */
    public static StandardSignature signStandard(byte[] message, BigInteger secretKey, BigInteger nonce) {
        BigInteger x = requireSecretKey(secretKey);
        BigInteger k = requireNonce(nonce);
        EcPoint r = CurveP256.mul(k, CurveP256.generator());
        EcPoint publicKey = CurveP256.mul(x, CurveP256.generator());
        BigInteger e = challenge(r, publicKey, message);
        BigInteger s = k.add(e.multiply(x)).mod(CurveP256.N);
        return new StandardSignature(r, s);
    }

    /** Verify a standard Schnorr signature against a single public key. */
    public static boolean verifyStandard(byte[] message, EcPoint publicKey, EcPoint r, BigInteger s) {
        if (!isValidScalar(s) || r == null || r.isInfinity()) {
            return false;
        }
        try {
            CurveP256.requireOnCurve(publicKey);
            CurveP256.requireOnCurve(r);
        } catch (IllegalArgumentException ex) {
            return false;
        }
        BigInteger e = challenge(r, publicKey, message);
        EcPoint left = CurveP256.mul(s, CurveP256.generator());
        EcPoint right = CurveP256.add(r, CurveP256.mul(e, publicKey));
        return left.equals(right);
    }

    /** Derive the public key for a secret key (validated to be in [1, n-1]). */
    public static EcPoint publicKeyFromSecret(BigInteger secretKey) {
        return CurveP256.mul(requireSecretKey(secretKey), CurveP256.generator());
    }

    /**
     * Key aggregation coefficient a_i for one participant in an ordered list.
     * Single-participant lists return 1 (plain Schnorr degeneration).
     */
    public static BigInteger keyAggregationCoefficient(List<EcPoint> orderedPublicKeys, int index) {
        if (orderedPublicKeys.size() == 1) {
            return BigInteger.ONE;
        }
        byte[] l = participantListHash(orderedPublicKeys);
        byte[] data = concat(l, encodePoint(orderedPublicKeys.get(index)));
        return CurveP256.scalarFrom32Bytes(taggedHash("KeyAgg/v1", data));
    }

    /** X = sum a_i * X_i, with on-curve and non-infinity validation. */
    public static EcPoint aggregatePublicKey(List<EcPoint> orderedPublicKeys) {
        EcPoint aggregate = new EcPoint(null, null);
        for (int i = 0; i < orderedPublicKeys.size(); i++) {
            EcPoint xi = orderedPublicKeys.get(i);
            CurveP256.requireOnCurve(xi);
            BigInteger ai = keyAggregationCoefficient(orderedPublicKeys, i);
            aggregate = CurveP256.add(aggregate, CurveP256.mul(ai, xi));
        }
        if (aggregate.isInfinity()) {
            throw new IllegalArgumentException("aggregate public key must not be the point at infinity");
        }
        return aggregate;
    }

    /** R = sum R_1i + b * sum R_2i, with b = H(X || R1sum || R2sum || m). */
    public static AggregateNonce aggregateNonce(List<NoncePair> pairs, EcPoint aggregateKey, byte[] message) {
        boolean single = isSingleNonceRound(pairs);
        EcPoint r1sum = new EcPoint(null, null);
        EcPoint r2sum = new EcPoint(null, null);
        for (NoncePair pair : pairs) {
            CurveP256.requireOnCurve(pair.r1());
            r1sum = CurveP256.add(r1sum, pair.r1());
            if (pair.r2() != null) {
                CurveP256.requireOnCurve(pair.r2());
                r2sum = CurveP256.add(r2sum, pair.r2());
            }
        }
        if (r1sum.isInfinity()) {
            throw new IllegalArgumentException("aggregate nonce must not be the point at infinity");
        }
        if (single) {
            return new AggregateNonce(r1sum, BigInteger.ZERO);
        }
        if (r2sum.isInfinity()) {
            throw new IllegalArgumentException("aggregate second nonce must not be the point at infinity");
        }
        byte[] data = concat(encodePoint(aggregateKey), encodePoint(r1sum), encodePoint(r2sum), message);
        BigInteger b = CurveP256.scalarFrom32Bytes(taggedHash("MuSig2/noncecoef/v1", data));
        EcPoint r = CurveP256.add(r1sum, CurveP256.mul(b, r2sum));
        if (r.isInfinity()) {
            throw new IllegalArgumentException("derived aggregate nonce is the point at infinity; retry with fresh nonces");
        }
        return new AggregateNonce(r, b);
    }

    /** Partial signature s_i = k1_i + b*k2_i + e*a_i*x_i (mod n). */
    public static BigInteger partialSignature(BigInteger secretKey, BigInteger k1, BigInteger k2,
                                              BigInteger coefficient, BigInteger b, BigInteger e) {
        BigInteger x = requireSecretKey(secretKey);
        BigInteger first = requireNonce(k1);
        BigInteger second = k2 == null ? BigInteger.ZERO : requireNonce(k2);
        BigInteger a = coefficient.mod(CurveP256.N);
        return first.add(b.multiply(second)).add(e.multiply(a).multiply(x)).mod(CurveP256.N);
    }

    /**
     * Verify a partial signature against the signer's public nonces:
     * s_i*G == R1_i + b*R2_i + e*a_i*X_i.
     */
    public static boolean verifyPartial(EcPoint r1, EcPoint r2, EcPoint publicKey,
                                        BigInteger sI, BigInteger coefficient, BigInteger b, BigInteger e) {
        if (!isValidScalar(sI)) {
            return false;
        }
        try {
            CurveP256.requireOnCurve(r1);
            CurveP256.requireOnCurve(publicKey);
            EcPoint left = CurveP256.mul(sI, CurveP256.generator());
            EcPoint right = r1;
            if (r2 != null && b.signum() != 0) {
                CurveP256.requireOnCurve(r2);
                right = CurveP256.add(right, CurveP256.mul(b, r2));
            }
            right = CurveP256.add(right, CurveP256.mul(e.multiply(coefficient).mod(CurveP256.N), publicKey));
            return left.equals(right);
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    /** s = sum s_i mod n. */
    public static BigInteger sumPartials(List<BigInteger> partialScalars) {
        BigInteger sum = BigInteger.ZERO;
        for (BigInteger partial : partialScalars) {
            if (!isValidScalar(partial)) {
                throw new IllegalArgumentException("partial signature scalar out of range");
            }
            sum = sum.add(partial);
        }
        return sum.mod(CurveP256.N);
    }

    /** Full aggregate verification: s*G == R + e*X. */
    public static boolean verifyAggregate(byte[] message, EcPoint aggregateKey, EcPoint r, BigInteger s) {
        return verifyStandard(message, aggregateKey, r, s);
    }

    /** Fiat-Shamir challenge e = H(R || X || m) reduced mod n. */
    public static BigInteger challenge(EcPoint r, EcPoint aggregateKey, byte[] message) {
        byte[] data = concat(encodePoint(r), encodePoint(aggregateKey), message);
        return CurveP256.scalarFrom32Bytes(taggedHash("SchnorrSign/v1", data));
    }

    private static boolean isSingleNonceRound(List<NoncePair> pairs) {
        for (NoncePair pair : pairs) {
            if (pair.r2() != null) {
                return false;
            }
        }
        return true;
    }

    private static byte[] participantListHash(List<EcPoint> orderedPublicKeys) {
        List<byte[]> encoded = new ArrayList<>(orderedPublicKeys.size());
        for (EcPoint point : orderedPublicKeys) {
            CurveP256.requireOnCurve(point);
            encoded.add(encodePoint(point));
        }
        return taggedHash("KeyAgg/list/v1", concat(encoded.toArray(new byte[0][])));
    }

    private static byte[] encodePoint(EcPoint point) {
        if (point == null || point.isInfinity()) {
            throw new IllegalArgumentException("point must not be infinity");
        }
        return hexToBytes(point.encodeCompressedHex());
    }

    private static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        byte[] out = new byte[length];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }

    private static BigInteger requireSecretKey(BigInteger secretKey) {
        if (secretKey == null || secretKey.signum() <= 0 || secretKey.compareTo(CurveP256.N) >= 0) {
            throw new IllegalArgumentException("secret key must be in [1, n-1]");
        }
        return secretKey;
    }

    private static BigInteger requireNonce(BigInteger nonce) {
        if (nonce == null || nonce.signum() <= 0 || nonce.compareTo(CurveP256.N) >= 0) {
            throw new IllegalArgumentException("nonce must be in [1, n-1]");
        }
        return nonce;
    }

    private static boolean isValidScalar(BigInteger scalar) {
        return scalar != null && scalar.signum() >= 0 && scalar.compareTo(CurveP256.N) < 0;
    }

    private static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    /** A standard Schnorr signature pair. */
    public record StandardSignature(EcPoint r, BigInteger s) {
    }

    /** Aggregate nonce together with the coefficient b used to derive it. */
    public record AggregateNonce(EcPoint r, BigInteger b) {
    }

    /** A signer's two public nonces. */
    public record NoncePair(EcPoint r1, EcPoint r2) {
    }
}
