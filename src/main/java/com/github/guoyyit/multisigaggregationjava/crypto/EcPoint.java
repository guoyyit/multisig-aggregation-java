package com.github.guoyyit.multisigaggregationjava.crypto;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Immutable point on the P-256 (secp256r1 / NIST P-256) curve in affine
 * coordinates. The point at infinity is represented with {@code x == null}.
 */
public final class EcPoint {

    private final BigInteger x;
    private final BigInteger y;

    public EcPoint(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
    }

    public BigInteger x() {
        return x;
    }

    public BigInteger y() {
        return y;
    }

    public boolean isInfinity() {
        return x == null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof EcPoint other)) {
            return false;
        }
        if (isInfinity() || other.isInfinity()) {
            return isInfinity() && other.isInfinity();
        }
        return x.equals(other.x) && y.equals(other.y);
    }

    @Override
    public int hashCode() {
        return isInfinity() ? 0 : x.hashCode() * 31 + y.hashCode();
    }

    public String encodeCompressedHex() {
        if (isInfinity()) {
            throw new IllegalStateException("cannot encode the point at infinity");
        }
        byte[] out = new byte[33];
        out[0] = (byte) (y.testBit(0) ? 0x03 : 0x02);
        byte[] xb = fixed32(x);
        System.arraycopy(xb, 0, out, 1, 32);
        return toHex(out);
    }

    public static EcPoint decodeCompressedHex(String hex) {
        byte[] bytes = fromHex(hex);
        if (bytes.length == 33) {
            int prefix = bytes[0] & 0xFF;
            if (prefix != 0x02 && prefix != 0x03) {
                throw new IllegalArgumentException("unsupported compressed point prefix");
            }
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(bytes, 1, 33));
            return decompress(x, prefix == 0x03);
        }
        if (bytes.length == 65) {
            int prefix = bytes[0] & 0xFF;
            if (prefix != 0x04) {
                throw new IllegalArgumentException("unsupported uncompressed point prefix");
            }
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(bytes, 1, 33));
            BigInteger y = new BigInteger(1, Arrays.copyOfRange(bytes, 33, 65));
            EcPoint point = new EcPoint(x, y);
            CurveP256.requireOnCurve(point);
            return point;
        }
        throw new IllegalArgumentException("point encoding must be 33 or 65 bytes");
    }

    private static EcPoint decompress(BigInteger x, boolean oddY) {
        if (x.signum() < 0 || x.compareTo(CurveP256.P) >= 0) {
            throw new IllegalArgumentException("x coordinate out of field range");
        }
        BigInteger rhs = x.pow(3).add(CurveP256.A.multiply(x)).add(CurveP256.B)
                .mod(CurveP256.P);
        BigInteger y = rhs.modPow(CurveP256.P.add(BigInteger.ONE).shiftRight(2), CurveP256.P);
        if (!y.pow(2).mod(CurveP256.P).equals(rhs)) {
            throw new IllegalArgumentException("compressed point is not on P-256");
        }
        if (y.testBit(0) != oddY) {
            y = CurveP256.P.subtract(y);
        }
        EcPoint point = new EcPoint(x, y);
        CurveP256.requireOnCurve(point);
        return point;
    }

    private static byte[] fixed32(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[32];
        if (raw.length >= 32) {
            System.arraycopy(raw, raw.length - 32, out, 0, 32);
        } else {
            System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        }
        return out;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    private static byte[] fromHex(String hex) {
        if (hex == null) {
            throw new IllegalArgumentException("hex string must not be null");
        }
        String s = hex.trim();
        if (s.length() % 2 != 0) {
            throw new IllegalArgumentException("hex string must have even length");
        }
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int high = Character.digit(s.charAt(i * 2), 16);
            int low = Character.digit(s.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("invalid hex digit");
            }
            out[i] = (byte) ((high << 4) + low);
        }
        return out;
    }
}
