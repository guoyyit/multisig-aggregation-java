package com.github.guoyyit.multisigaggregationjava.core;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

public final class Musig {

    public static final String COEF_TAG = "multisig-coefficient/v1";
    public static final String COMMIT_TAG = "multisig-commitment/v1";
    private static final SecureRandom RANDOM = new SecureRandom();

    private Musig() {
    }

    /**
     * 按压缩编码字典序排序，保证所有参与方计算出的聚合公钥与系数顺序一致。
     */
    public static List<ECPoint> sortPoints(List<ECPoint> publicKeys) {
        return publicKeys.stream()
                .map(ECPoint::normalize)
                .sorted(Comparator.comparing(p -> java.util.HexFormat.of().formatHex(Schnorr.compress(p))))
                .toList();
    }

    /**
     * 单个签名方时系数固定为 1，聚合退化为普通 Schnorr 公钥，保证单签互通。
     */
    public static BigInteger coefficient(List<ECPoint> sortedPublicKeys, ECPoint member) {
        byte[] memberBytes = Schnorr.compress(member.normalize());
        if (sortedPublicKeys.size() == 1) {
            if (!sortedPublicKeys.get(0).equals(member.normalize())) {
                throw new IllegalArgumentException("单签集合中不包含该公钥");
            }
            return BigInteger.ONE;
        }
        byte[] joined = new byte[sortedPublicKeys.size() * 33];
        for (int i = 0; i < sortedPublicKeys.size(); i++) {
            System.arraycopy(Schnorr.compress(sortedPublicKeys.get(i)), 0, joined, i * 33, 33);
        }
        byte[] input = concat(memberBytes, joined);
        byte[] hash = Schnorr.taggedHash(COEF_TAG, input);
        return new BigInteger(1, hash).mod(Schnorr.curveOrder());
    }

    public static ECPoint aggregatePoint(List<ECPoint> sortedPublicKeys) {
        ECPoint acc = sortedPublicKeys.get(0).getCurve().getInfinity();
        for (ECPoint point : sortedPublicKeys) {
            BigInteger coefficient = coefficient(sortedPublicKeys, point);
            acc = acc.add(point.multiply(coefficient));
        }
        return acc.normalize();
    }

    public static byte[] commitment(String sessionId, byte[] nonceCompressed, byte[] salt) {
        byte[] sessionBytes = sessionId.getBytes(StandardCharsets.UTF_8);
        return Schnorr.taggedHash(COMMIT_TAG, concat(sessionBytes, salt, nonceCompressed));
    }

    public static byte[] sessionSalt() {
        byte[] salt = new byte[32];
        RANDOM.nextBytes(salt);
        return salt;
    }

    /**
     * 部分签名校验所用的有效公钥：a_i * X_i。
     */
    public static ECPoint effectivePublicKey(List<ECPoint> sortedPublicKeys, ECPoint member) {
        return member.multiply(coefficient(sortedPublicKeys, member)).normalize();
    }

    public static String compressedHex(List<ECPoint> points) {
        return points.stream()
                .map(p -> java.util.HexFormat.of().formatHex(Schnorr.compress(p)))
                .collect(Collectors.joining(","));
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
}
