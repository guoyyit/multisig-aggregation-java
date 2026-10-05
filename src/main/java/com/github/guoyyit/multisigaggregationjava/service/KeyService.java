package com.github.guoyyit.multisigaggregationjava.service;

import com.github.guoyyit.multisigaggregationjava.core.ErrorCode;
import com.github.guoyyit.multisigaggregationjava.core.Hex;
import com.github.guoyyit.multisigaggregationjava.core.Schnorr;
import com.github.guoyyit.multisigaggregationjava.core.ServiceException;
import com.github.guoyyit.multisigaggregationjava.model.KeyStatus;
import com.github.guoyyit.multisigaggregationjava.model.ProofStatus;
import com.github.guoyyit.multisigaggregationjava.model.PublicKeyRecord;
import com.github.guoyyit.multisigaggregationjava.store.AuditLog;
import com.github.guoyyit.multisigaggregationjava.store.KeyRepository;
import org.bouncycastle.math.ec.ECPoint;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;

@Service
public class KeyService {

    private final KeyRepository keys;
    private final AuditLog audit;

    public KeyService(KeyRepository keys, AuditLog audit) {
        this.keys = keys;
        this.audit = audit;
    }

    /**
     * 注册公钥必须同时提交对该公钥的所有权证明（Schnorr PoP）。
     * 同一 keyId 以完全相同内容重复注册视为幂等成功。
     */
    public PublicKeyRecord register(String keyId, String owner, String pubHex, String popHex) {
        validateId(keyId);
        ECPoint point = parsePublicKey(pubHex);
        if (popHex == null || popHex.isBlank()) {
            throw new ServiceException(ErrorCode.POP_MISSING);
        }
        String canonicalPop;
        try {
            canonicalPop = Hex.encode(Hex.decode(popHex.trim()));
        } catch (IllegalArgumentException ex) {
            throw new ServiceException(ErrorCode.POP_INVALID, "PoP 编码无效");
        }
        if (!Schnorr.verifyPop(point, Hex.decode(canonicalPop))) {
            throw new ServiceException(ErrorCode.POP_INVALID);
        }
        ReentrantLock global = keys.registrationLock();
        ReentrantLock lock = keys.lock(keyId);
        global.lock();
        lock.lock();
        try {
            PublicKeyRecord existing = keys.findById(keyId).orElse(null);
            if (existing != null) {
                if (existing.status() == KeyStatus.REVOKED
                        && existing.proofStatus()
                        == ProofStatus.NOT_APPLICABLE) {
                    throw new ServiceException(ErrorCode.KEY_REVOKED,
                            "该 keyId 已先于注册被撤销（撤销墓碑），禁止注册覆盖撤销");
                }
                if (existing.status() != KeyStatus.ACTIVE
                        || !safeEquals(existing.pubHex(), canonicalHex(pubHex))
                        || !safeEquals(existing.owner(), owner)) {
                    throw new ServiceException(ErrorCode.DUPLICATE_KEY_ID,
                            "keyId 已存在且内容不一致");
                }
                return existing;
            }
            String canonicalPub = canonicalHex(pubHex);
            for (PublicKeyRecord other : keys.findAll()) {
                if (other.status() == KeyStatus.ACTIVE
                        && other.pubHex().equals(canonicalPub)) {
                    throw new ServiceException(ErrorCode.DUPLICATE_PUBLIC_KEY,
                            "同一公钥已以 keyId=" + other.keyId() + " 注册");
                }
            }
            PublicKeyRecord record = new PublicKeyRecord(
                    keyId, owner, canonicalPub, canonicalPop,
                    ProofStatus.PRESENT,
                    KeyStatus.ACTIVE, 1,
                    System.currentTimeMillis(), 0L, null);
            keys.put(record);
            audit.append("KEY_REGISTERED", keyId, null,
                    "owner=" + owner + ", pub=" + record.pubHex()
                            + ", proofStatus=PRESENT, popFingerprint=" + popFingerprint(canonicalPop));
            return record;
        } finally {
            if (lock.isHeldByCurrentThread()) {
                lock.unlock();
            }
            if (global.isHeldByCurrentThread()) {
                global.unlock();
            }
        }
    }

    /**
     * 轮换：旧密钥标记为 SUPERSEDED，新密钥注册为 ACTIVE；旧会话与历史签名不受影响。
     */
    public PublicKeyRecord rotate(String oldKeyId, String newKeyId, String newPubHex, String popHex) {
        validateId(oldKeyId);
        validateId(newKeyId);
        if (oldKeyId.equals(newKeyId)) {
            throw new ServiceException(ErrorCode.VALIDATION_ERROR, "新旧 keyId 不能相同");
        }
        PublicKeyRecord oldRecord = requireActive(oldKeyId);
        ECPoint point = parsePublicKey(newPubHex);
        if (popHex == null || popHex.isBlank()) {
            throw new ServiceException(ErrorCode.POP_MISSING);
        }
        String canonicalPop;
        try {
            canonicalPop = Hex.encode(Hex.decode(popHex.trim()));
        } catch (IllegalArgumentException ex) {
            throw new ServiceException(ErrorCode.POP_INVALID, "PoP 编码无效");
        }
        if (!Schnorr.verifyPop(point, Hex.decode(canonicalPop))) {
            throw new ServiceException(ErrorCode.POP_INVALID);
        }
        ReentrantLock global = keys.registrationLock();
        ReentrantLock oldLock = keys.lock(oldKeyId);
        ReentrantLock newLock = keys.lock(newKeyId);
        global.lock();
        lockBoth(oldLock, newLock);
        try {
            PublicKeyRecord reloadedOld = keys.findById(oldKeyId)
                    .orElseThrow(() -> new ServiceException(ErrorCode.KEY_NOT_FOUND));
            if (reloadedOld.status() == KeyStatus.REVOKED) {
                throw new ServiceException(ErrorCode.KEY_REVOKED, "已撤销密钥不能轮换");
            }
            if (keys.findById(newKeyId).isPresent()) {
                throw new ServiceException(ErrorCode.DUPLICATE_KEY_ID, "新 keyId 已存在");
            }
            String canonicalNew = canonicalHex(newPubHex);
            for (PublicKeyRecord other : keys.findAll()) {
                if (other.status() == KeyStatus.ACTIVE && other.pubHex().equals(canonicalNew)) {
                    throw new ServiceException(ErrorCode.DUPLICATE_PUBLIC_KEY,
                            "同一公钥已以 keyId=" + other.keyId() + " 注册");
                }
            }
            PublicKeyRecord superseded = new PublicKeyRecord(
                    reloadedOld.keyId(), reloadedOld.owner(), reloadedOld.pubHex(),
                    reloadedOld.popHex(), reloadedOld.proofStatus(),
                    KeyStatus.SUPERSEDED, reloadedOld.version() + 1,
                    reloadedOld.registeredAt(), System.currentTimeMillis(), newKeyId);
            PublicKeyRecord fresh = new PublicKeyRecord(
                    newKeyId, reloadedOld.owner(), canonicalNew, canonicalPop,
                    ProofStatus.PRESENT, KeyStatus.ACTIVE, 1,
                    System.currentTimeMillis(), 0L, null);
            keys.put(superseded);
            keys.put(fresh);
            audit.append("KEY_ROTATED", oldKeyId, null, "replacedBy=" + newKeyId);
            audit.append("KEY_REGISTERED", newKeyId, null,
                    "rotatedFrom=" + oldKeyId + ", pub=" + fresh.pubHex()
                            + ", proofStatus=PRESENT, popFingerprint=" + popFingerprint(canonicalPop));
            return fresh;
        } finally {
            if (oldLock.isHeldByCurrentThread()) {
                oldLock.unlock();
            }
            if (newLock.isHeldByCurrentThread()) {
                newLock.unlock();
            }
            if (global.isHeldByCurrentThread()) {
                global.unlock();
            }
        }
    }

    /**
     * 撤销：密钥立即不能参与新会话；历史会话文件中的快照公钥仍可验证历史聚合签名。
     */
    public PublicKeyRecord revoke(String keyId, String reason) {
        ReentrantLock global = keys.registrationLock();
        ReentrantLock lock = keys.lock(keyId);
        global.lock();
        lock.lock();
        try {
            PublicKeyRecord record = keys.findById(keyId).orElse(null);
            if (record == null) {
                // 先撤销后注册：写入撤销墓碑，随后的注册必须被明确拒绝；
                // 墓碑没有公钥材料，因此不参与任何公钥查重。
                long now = System.currentTimeMillis();
                PublicKeyRecord tombstone = new PublicKeyRecord(
                        keyId, "", null, null, ProofStatus.NOT_APPLICABLE,
                        KeyStatus.REVOKED, 1, now, now, null);
                keys.put(tombstone);
                audit.append("KEY_REVOKED", keyId, null,
                        "tombstone=true"
                                + (reason == null || reason.isBlank() ? "" : ", reason=" + reason));
                return tombstone;
            }
            if (record.status() == KeyStatus.REVOKED) {
                return record;
            }
            PublicKeyRecord revoked = new PublicKeyRecord(
                    record.keyId(), record.owner(), record.pubHex(),
                    record.popHex(), record.proofStatus(), KeyStatus.REVOKED,
                    record.version() + 1, record.registeredAt(),
                    System.currentTimeMillis(), record.replacedById());
            keys.put(revoked);
            audit.append("KEY_REVOKED", keyId, null,
                    "tombstone=false" + (reason == null ? "" : ", reason=" + reason));
            return revoked;
        } finally {
            lock.unlock();
            global.unlock();
        }
    }

    public Optional<PublicKeyRecord> get(String keyId) {
        return keys.findById(keyId);
    }

    /**
     * 用注册时持久化的所有权证明重新验证对应公钥。
     * 升级前旧记录（LEGACY_MISSING）与撤销墓碑（NOT_APPLICABLE）无证明可验，
     * 返回各自可解释状态，由调用方区分。
     */
    public ProofVerification verifyStoredProof(String keyId) {
        PublicKeyRecord record = keys.findById(keyId)
                .orElseThrow(() -> new ServiceException(ErrorCode.KEY_NOT_FOUND));
        if (record.proofStatus() != ProofStatus.PRESENT) {
            return new ProofVerification(record.proofStatus(), false);
        }
        ECPoint point = parsePublicKey(record.pubHex());
        boolean valid = Schnorr.verifyPop(point, Hex.decode(record.popHex()));
        return new ProofVerification(ProofStatus.PRESENT, valid);
    }

    public record ProofVerification(ProofStatus proofStatus, boolean valid) {
    }

    public List<PublicKeyRecord> list(KeyStatus status) {
        return status == null ? keys.findAll() : keys.findByStatus(status);
    }

    public PublicKeyRecord requireActive(String keyId) {
        PublicKeyRecord record = keys.findById(keyId)
                .orElseThrow(() -> new ServiceException(ErrorCode.KEY_NOT_FOUND,
                        "公钥不存在: " + keyId));
        if (record.status() == KeyStatus.REVOKED) {
            throw new ServiceException(ErrorCode.KEY_REVOKED, "公钥已撤销: " + keyId);
        }
        if (record.status() == KeyStatus.SUPERSEDED) {
            throw new ServiceException(ErrorCode.KEY_SUPERSEDED,
                    "公钥已被轮换: " + keyId + " -> " + record.replacedById());
        }
        return record;
    }

    public ECPoint publicPoint(String keyId) {
        return parsePublicKey(requireActive(keyId).pubHex());
    }

    static ECPoint parsePublicKey(String pubHex) {
        if (pubHex == null || pubHex.isBlank()) {
            throw new ServiceException(ErrorCode.INVALID_PUBLIC_KEY);
        }
        try {
            return Schnorr.parsePoint(Hex.decode(pubHex));
        } catch (RuntimeException ex) {
            throw new ServiceException(ErrorCode.INVALID_PUBLIC_KEY, ex.getMessage());
        }
    }

    static String canonicalHex(String pubHex) {
        return Hex.encode(Hex.decode(pubHex.trim().toLowerCase()));
    }

    /**
     * 审计中只记录证明内容的 SHA-256 指纹用于事后核对，绝不记录私钥材料，
     * 证明本身（对压缩公钥哈希的 Schnorr 签名）不含私钥，可完整持久化。
     */
    static String popFingerprint(String popHex) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Hex.encode(digest.digest(Hex.decode(popHex)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static void validateId(String id) {
        if (id == null || !id.matches("[A-Za-z0-9._-]{1,128}")) {
            throw new ServiceException(ErrorCode.VALIDATION_ERROR, "ID 必须为 1-128 位字母数字._-");
        }
    }

    private static boolean safeEquals(String a, String b) {
        return a == null ? b == null : a.equals(b);
    }

    private static void lockBoth(ReentrantLock first, ReentrantLock second) {
        if (first == second) {
            first.lock();
            return;
        }
        first.lock();
        try {
            second.lock();
        } catch (RuntimeException ex) {
            first.unlock();
            throw ex;
        }
    }
}
