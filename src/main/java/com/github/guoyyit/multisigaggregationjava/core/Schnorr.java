package com.github.guoyyit.multisigaggregationjava.core;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public final class Schnorr {

    public static final String POP_TAG = "multisig-pop/v1";
    public static final String CHALLENGE_TAG = "BIP0340/challenge";

    private static final X9ECParameters PARAMETERS = SECNamedCurves.getByName("secp256k1");
    private static final ECDomainParameters DOMAIN =
            new ECDomainParameters(PARAMETERS.getCurve(), PARAMETERS.getG(), PARAMETERS.getN(), PARAMETERS.getH());
    private static final SecureRandom RANDOM = new SecureRandom();

    static {
        // 触发曲线类加载，确认 BouncyCastle 提供者在类路径上。
        new SecP256K1Curve();
    }

    private Schnorr() {
    }

    public static ECPoint generator() {
        return DOMAIN.getG();
    }

    public static BigInteger curveOrder() {
        return DOMAIN.getN();
    }

    public static ECPoint scalarBaseMult(BigInteger scalar) {
        return DOMAIN.getG().multiply(scalar).normalize();
    }

    public static ECPoint sum(ECPoint... points) {
        ECPoint acc = DOMAIN.getCurve().getInfinity();
        for (ECPoint point : points) {
            if (point != null) {
                acc = acc.add(point);
            }
        }
        return acc.normalize();
    }

    public static byte[] compress(ECPoint point) {
        return point.getEncoded(true);
    }

    public static ECPoint parsePoint(byte[] compressed) {
        if (compressed == null) {
            throw new IllegalArgumentException("点编码为空");
        }
        try {
            ECPoint point = DOMAIN.getCurve().decodePoint(compressed).normalize();
            if (point.isInfinity() || !point.isValid()) {
                throw new IllegalArgumentException("点不在曲线上");
            }
            return point;
        } catch (RuntimeException ex) {
            throw new IllegalArgumentException("点编码无效", ex);
        }
    }

    public static byte[] taggedHash(String tag, byte[] message) {
        SHA256Digest tagDigest = new SHA256Digest();
        byte[] tagBytes = tag.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        tagDigest.update(tagBytes, 0, tagBytes.length);
        byte[] tagHash = new byte[32];
        tagDigest.doFinal(tagHash, 0);

        SHA256Digest digest = new SHA256Digest();
        digest.update(tagHash, 0, tagHash.length);
        digest.update(tagHash, 0, tagHash.length);
        digest.update(message, 0, message.length);
        byte[] out = new byte[32];
        digest.doFinal(out, 0);
        return out;
    }

    public static BigInteger challenge(ECPoint nonceSum, ECPoint publicKey, byte[] message) {
        byte[] input = concat(compress(nonceSum), compress(publicKey), message);
        return new BigInteger(1, taggedHash(CHALLENGE_TAG, input)).mod(DOMAIN.getN());
    }

    public static byte[] signSchnorr(BigInteger secret, byte[] message, SecureRandom random) {
        BigInteger n = DOMAIN.getN();
        if (secret == null || secret.signum() <= 0 || secret.compareTo(n) >= 0) {
            throw new IllegalArgumentException("私钥不在合法区间");
        }
        SecureRandom source = random != null ? random : RANDOM;
        ECPoint publicKey = scalarBaseMult(secret);
        BigInteger k;
        do {
            k = randomScalar(source);
        } while (k.signum() == 0);
        ECPoint nonce = scalarBaseMult(k);
        BigInteger e = challenge(nonce, publicKey, message);
        BigInteger s = k.add(e.multiply(secret)).mod(n);
        return encodeSignature(compress(nonce), s);
    }

    public static boolean verifySchnorr(ECPoint publicKey, byte[] message, byte[] signature) {
        try {
            ParsedSignature parsed = parseSignature(signature);
            return verifyFull(publicKey, message, parsed.nonce(), parsed.s());
        } catch (RuntimeException ex) {
            return false;
        }
    }

    public static boolean verifyFull(ECPoint publicKey, byte[] message, ECPoint nonce, BigInteger s) {
        if (publicKey == null || nonce == null || s == null || message == null) {
            return false;
        }
        BigInteger n = DOMAIN.getN();
        if (s.signum() <= 0 || s.compareTo(n) >= 0) {
            return false;
        }
        BigInteger e = challenge(nonce, publicKey, message);
        ECPoint left = scalarBaseMult(s);
        ECPoint right = sum(nonce, publicKey.multiply(e));
        return left.equals(right);
    }

    public static byte[] popMessage(byte[] compressedPublicKey) {
        return taggedHash(POP_TAG, compressedPublicKey);
    }

    public static byte[] signPop(BigInteger secret, byte[] compressedPublicKey, SecureRandom random) {
        return signSchnorr(secret, popMessage(compressedPublicKey), random);
    }

    public static boolean verifyPop(ECPoint publicKey, byte[] proof) {
        if (publicKey == null || proof == null) {
            return false;
        }
        return verifySchnorr(publicKey, popMessage(compress(publicKey)), proof);
    }

    public static BigInteger randomScalar(SecureRandom random) {
        BigInteger n = DOMAIN.getN();
        byte[] raw = new byte[32];
        random.nextBytes(raw);
        BigInteger value = new BigInteger(1, raw).mod(n.subtract(BigInteger.ONE));
        return value.add(BigInteger.ONE);
    }

    public static byte[] scalarToBytes(BigInteger scalar) {
        byte[] bytes = scalar.mod(DOMAIN.getN()).toByteArray();
        if (bytes.length == 32) {
            return bytes;
        }
        byte[] fixed = new byte[32];
        if (bytes.length > 32) {
            System.arraycopy(bytes, bytes.length - 32, fixed, 0, 32);
        } else {
            System.arraycopy(bytes, 0, fixed, 32 - bytes.length, bytes.length);
        }
        return fixed;
    }

    public static BigInteger bytesToScalar(byte[] bytes) {
        if (bytes == null || bytes.length != 32) {
            throw new IllegalArgumentException("标量必须为 32 字节");
        }
        return new BigInteger(1, bytes).mod(DOMAIN.getN());
    }

    public static byte[] encodeSignature(ECPoint nonce, BigInteger s) {
        return encodeSignature(compress(nonce), s);
    }

    private static byte[] encodeSignature(byte[] nonceCompressed, BigInteger s) {
        return concat(nonceCompressed, scalarToBytes(s));
    }

    public static ParsedSignature parseSignature(byte[] signature) {
        if (signature == null || signature.length != 65) {
            throw new IllegalArgumentException("签名必须为 65 字节（33 字节压缩点 + 32 字节标量）");
        }
        ECPoint nonce = parsePoint(Arrays.copyOfRange(signature, 0, 33));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, 33, 65));
        if (s.signum() <= 0 || s.compareTo(DOMAIN.getN()) >= 0) {
            throw new IllegalArgumentException("签名标量越界");
        }
        return new ParsedSignature(nonce, s);
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

    public record ParsedSignature(ECPoint nonce, BigInteger s) {
    }
}
