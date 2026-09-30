package com.github.guoyyit.multisigaggregationjava.signer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.guoyyit.multisigaggregationjava.core.Hex;
import com.github.guoyyit.multisigaggregationjava.core.Musig;
import com.github.guoyyit.multisigaggregationjava.core.Schnorr;
import com.github.guoyyit.multisigaggregationjava.store.FileStore;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.List;

/**
 * 本地测试用签名方：私钥与随机数派生种子持久化在本地文件，
 * 随机数由 seed 与 sessionId 确定性派生，保证每个会话唯一且重启后仍可复现；
 * 不同会话派生出不同随机数点，服务端随机数账本提供第二道重用拦截。
 */
public class LocalSigner {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final String keyId;
    private final BigInteger secret;
    private final BigInteger seed;
    private final FileStore store;

    private LocalSigner(String keyId, BigInteger secret, BigInteger seed, FileStore store) {
        this.keyId = keyId;
        this.secret = secret;
        this.seed = seed;
        this.store = store;
    }

    public String keyId() {
        return keyId;
    }

    public static LocalSigner generate(String keyId, FileStore store) {
        BigInteger secret = Schnorr.randomScalar(RANDOM);
        byte[] seedBytes = new byte[32];
        RANDOM.nextBytes(seedBytes);
        ObjectNode node = JsonNodeFactory.instance.objectNode();
        node.put("keyId", keyId);
        node.put("secretHex", Hex.encode(Schnorr.scalarToBytes(secret)));
        node.put("seedHex", Hex.encode(seedBytes));
        store.atomicWriteJson(signerFile(store, keyId), node);
        return new LocalSigner(keyId, secret, new BigInteger(1, seedBytes), store);
    }

    public static LocalSigner load(String keyId, FileStore store) {
        JsonNode node = store.readJson(signerFile(store, keyId), JsonNode.class);
        if (node == null) {
            throw new IllegalStateException("签名方密钥未持久化: " + keyId);
        }
        BigInteger secret = Schnorr.bytesToScalar(Hex.decode(node.get("secretHex").asText()));
        BigInteger seed = new BigInteger(1, Hex.decode(node.get("seedHex").asText()));
        return new LocalSigner(keyId, secret, seed, store);
    }

    public static LocalSigner loadOrGenerate(String keyId, FileStore store) {
        return store.readJson(signerFile(store, keyId), JsonNode.class) == null
                ? generate(keyId, store) : load(keyId, store);
    }

    public String publicKeyHex() {
        return Hex.encode(Schnorr.compress(Schnorr.scalarBaseMult(secret)));
    }

    public String proofOfPossessionHex() {
        byte[] pub = Hex.decode(publicKeyHex());
        return Hex.encode(Schnorr.signPop(secret, pub, RANDOM));
    }

    public String commitment(String sessionId, String saltHex) {
        byte[] nonce = Schnorr.compress(noncePoint(sessionId));
        return Hex.encode(Musig.commitment(sessionId, nonce, Hex.decode(saltHex)));
    }

    public String nonce(String sessionId) {
        return Hex.encode(Schnorr.compress(noncePoint(sessionId)));
    }

    /**
     * 计算部分签名 s_i = k_i + e * a_i * x_i (mod n)。
     */
    public String partialSignature(String sessionId, String messageHex,
                                   List<String> allPubHex, List<String> nonceHexes) {
        List<ECPoint> sorted = allPubHex.stream()
                .map(hex -> Schnorr.parsePoint(Hex.decode(hex)))
                .sorted((a, b) -> Hex.encode(Schnorr.compress(a))
                        .compareTo(Hex.encode(Schnorr.compress(b))))
                .toList();
        ECPoint ownPoint = Schnorr.scalarBaseMult(secret);
        BigInteger coefficient = Musig.coefficient(sorted, ownPoint);

        ECPoint nonceSum = Schnorr.generator().getCurve().getInfinity();
        for (String nonceHex : nonceHexes) {
            nonceSum = nonceSum.add(Schnorr.parsePoint(Hex.decode(nonceHex)));
        }
        nonceSum = nonceSum.normalize();

        ECPoint aggregate = Musig.aggregatePoint(sorted);
        byte[] message = Hex.decode(messageHex);
        BigInteger e = Schnorr.challenge(nonceSum, aggregate, message);
        BigInteger k = nonceScalar(sessionId);
        BigInteger s = k.add(e.multiply(coefficient).multiply(secret)).mod(Schnorr.curveOrder());
        return Hex.encode(Schnorr.encodeSignature(noncePoint(sessionId), s));
    }

    public BigInteger nonceScalar(String sessionId) {
        byte[] material = concat(
                Schnorr.scalarToBytes(seed),
                sessionId.getBytes(StandardCharsets.UTF_8));
        byte[] hash = Schnorr.taggedHash("multisig-signer-nonce/v1", material);
        BigInteger k = new BigInteger(1, hash).mod(Schnorr.curveOrder());
        return k.signum() == 0 ? BigInteger.ONE : k;
    }

    private ECPoint noncePoint(String sessionId) {
        return Schnorr.scalarBaseMult(nonceScalar(sessionId)).normalize();
    }

    private static Path signerFile(FileStore store, String keyId) {
        if (!keyId.matches("[A-Za-z0-9._-]{1,128}")) {
            throw new IllegalArgumentException("非法 keyId");
        }
        return store.signersDir().resolve(keyId + ".json");
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
