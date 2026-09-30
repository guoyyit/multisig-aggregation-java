package com.github.guoyyit.multisigaggregationjava.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Group operations on NIST P-256 (y^2 = x^3 - 3x + b mod p), with the
 * cofactor-correct generator G and prime order n.
 */
public final class CurveP256 {

    public static final BigInteger P = new BigInteger(1, hex(
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"));
    public static final BigInteger A = P.subtract(BigInteger.valueOf(3));
    public static final BigInteger B = new BigInteger(1, hex(
            "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"));
    public static final BigInteger N = new BigInteger(1, hex(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"));

    private static final BigInteger GX = new BigInteger(1, hex(
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"));
    private static final BigInteger GY = new BigInteger(1, hex(
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"));
    private static final EcPoint G = new EcPoint(GX, GY);

    private static final SecureRandom RANDOM = new SecureRandom();

    private CurveP256() {
    }

    /** The generator G. */
    public static EcPoint generator() {
        return G;
    }

    /** Scalar multiplication k * point with full curve-membership validation. */
    public static EcPoint mul(BigInteger k, EcPoint point) {
        requireOnCurve(point);
        BigInteger scalar = k.mod(N);
        if (scalar.signum() == 0) {
            return new EcPoint(null, null);
        }
        EcPoint result = point;
        for (int bit = scalar.bitLength() - 2; bit >= 0; bit--) {
            result = doublePoint(result);
            if (scalar.testBit(bit)) {
                result = add(result, point);
            }
        }
        return result;
    }

    /** Point addition. */
    public static EcPoint add(EcPoint p, EcPoint q) {
        if (p.isInfinity()) {
            return q;
        }
        if (q.isInfinity()) {
            return p;
        }
        if (p.x().equals(q.x())) {
            if (p.y().equals(q.y())) {
                return doublePoint(p);
            }
            return new EcPoint(null, null);
        }
        BigInteger slope = q.y().subtract(p.y())
                .multiply(q.x().subtract(p.x()).modInverse(P))
                .mod(P);
        BigInteger rx = slope.pow(2).subtract(p.x()).subtract(q.x()).mod(P);
        BigInteger ry = slope.multiply(p.x().subtract(rx)).subtract(p.y()).mod(P);
        return new EcPoint(rx, ry);
    }

    /** Point negation. */
    public static EcPoint neg(EcPoint p) {
        if (p.isInfinity()) {
            return p;
        }
        return new EcPoint(p.x(), P.subtract(p.y()).mod(P));
    }

    /** Re-encodes and validates that a decoded point lies on the curve. */
    public static void requireOnCurve(EcPoint point) {
        if (point == null || point.isInfinity()) {
            throw new IllegalArgumentException("point must not be infinity");
        }
        BigInteger x = point.x();
        BigInteger y = point.y();
        if (x.signum() < 0 || x.compareTo(P) >= 0 || y.signum() < 0 || y.compareTo(P) >= 0) {
            throw new IllegalArgumentException("point coordinates out of field range");
        }
        BigInteger lhs = y.pow(2).mod(P);
        BigInteger rhs = x.pow(3).add(A.multiply(x)).add(B).mod(P);
        if (!lhs.equals(rhs)) {
            throw new IllegalArgumentException("point is not on P-256");
        }
    }

    /** Uniform random scalar in [1, n-1] from a SecureRandom. */
    public static BigInteger randomScalar() {
        byte[] bytes = new byte[32];
        BigInteger candidate;
        do {
            RANDOM.nextBytes(bytes);
            candidate = new BigInteger(1, bytes).mod(N);
        } while (candidate.signum() == 0);
        return candidate;
    }

    /** Canonical byte encoding of a scalar (32 bytes, big-endian). */
    public static byte[] scalarBytes(BigInteger scalar) {
        byte[] raw = scalar.mod(N).toByteArray();
        byte[] out = new byte[32];
        if (raw.length >= 32) {
            System.arraycopy(raw, raw.length - 32, out, 0, 32);
        } else {
            System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        }
        return out;
    }

    /** Reduce a 32-byte big-endian value mod n into [0, n-1]. */
    public static BigInteger scalarFrom32Bytes(byte[] bytes) {
        if (bytes == null || bytes.length != 32) {
            throw new IllegalArgumentException("expected exactly 32 bytes");
        }
        return new BigInteger(1, bytes).mod(N);
    }

    private static EcPoint doublePoint(EcPoint p) {
        BigInteger slope = p.x().pow(2).multiply(BigInteger.valueOf(3)).add(A)
                .multiply(p.y().shiftLeft(1).modInverse(P))
                .mod(P);
        BigInteger rx = slope.pow(2).subtract(p.x().shiftLeft(1)).mod(P);
        BigInteger ry = slope.multiply(p.x().subtract(rx)).subtract(p.y()).mod(P);
        return new EcPoint(rx, ry);
    }

    private static byte[] hex(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
