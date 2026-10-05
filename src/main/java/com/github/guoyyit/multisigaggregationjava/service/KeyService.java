package com.github.guoyyit.multisigaggregationjava.service;

import com.github.guoyyit.multisigaggregationjava.core.ErrorCode;
import com.github.guoyyit.multisigaggregationjava.core.Hex;
import com.github.guoyyit.multisigaggregationjava.core.Schnorr;
import com.github.guoyyit.multisigaggregationjava.core.ServiceException;
import com.github.guoyyit.multisigaggregationjava.model.KeyStatus;
import com.github.guoyyit.multisigaggregationjava.model.PublicKeyRecord;
import com.github.guoyyit.multisigaggregationjava.store.AuditLog;
import com.github.guoyyit.multisigaggregationjava.store.KeyRepository;
import org.bouncycastle.math.ec.ECPoint;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
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
     * 锁序固定为 keyId 锁 → 全局注册锁，持锁期间不再获取其他锁，避免死锁。
     */
    public PublicKeyRecord register(String keyId, String owner, String pubHex, String popHex) {
        validateId(keyId);
        ECPoint point = parsePublicKey(pubHex);
        if (popHex == null || popHex.isBlank()) {
            throw new ServiceException(ErrorCode.POP_MISSING);
        }
        byte[] proof;
        try {
            proof = Hex.decode(popHex);
        } catch (IllegalArgumentException ex) {
            throw new ServiceException(ErrorCode.POP_INVALID, "PoP 编码无效");
        }
        if (!Schnorr.verifyPop(point, proof)) {
            throw new ServiceException(ErrorCode.POP_INVALID);
        }
        ReentrantLock lock = keys.lock(keyId);
        lock.lock();
        try {
            ReentrantLock registration = keys.registrationLock();
            registration.lock();
            try {
                PublicKeyRecord existing = keys.findById(keyId).orElse(null);
                if (existing != null) {
                    if (existing.status() != KeyStatus.ACTIVE
                            || !safeEquals(existing.pubHex(), canonicalHex(pubHex))
                            || !safeEquals(existing.owner(), owner)) {
                        throw new ServiceException(ErrorCode.DUPLICATE_KEY_ID,
                                "keyId 已存在且内容不一致");
                    }
                    return existing;
                }
                for (PublicKeyRecord other : keys.findAll()) {
                    if (other.status() == KeyStatus.ACTIVE
                            && other.pubHex().equals(canonicalHex(pubHex))) {
                        throw new ServiceException(ErrorCode.DUPLICATE_PUBLIC_KEY,
                                "同一公钥已以 keyId=" + other.keyId() + " 注册");
                    }
                }
                PublicKeyRecord record = new PublicKeyRecord(
                        keyId, owner, canonicalHex(pubHex), KeyStatus.ACTIVE, 1,
                        System.currentTimeMillis(), 0L, null, popHex);
                keys.put(record);
                audit.append("KEY_REGISTERED", keyId, null,
                        "owner=" + owner + ", pub=" + record.pubHex() + ", pop=" + popHex);
                return record;
            } finally {
                registration.unlock();
            }
        } finally {
            lock.unlock();
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
        if (popHex == null || !Schnorr.verifyPop(point, Hex.decode(popHex))) {
            throw new ServiceException(ErrorCode.POP_INVALID);
        }
        ReentrantLock oldLock = keys.lock(oldKeyId);
        ReentrantLock newLock = keys.lock(newKeyId);
        lockBoth(oldLock, newLock);
        try {
            ReentrantLock registration = keys.registrationLock();
            registration.lock();
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
                        KeyStatus.SUPERSEDED, reloadedOld.version() + 1,
                        reloadedOld.registeredAt(), System.currentTimeMillis(), newKeyId,
                        reloadedOld.popHex());
                PublicKeyRecord fresh = new PublicKeyRecord(
                        newKeyId, reloadedOld.owner(), canonicalNew, KeyStatus.ACTIVE, 1,
                        System.currentTimeMillis(), 0L, null, popHex);
                keys.put(superseded);
                keys.put(fresh);
                audit.append("KEY_ROTATED", oldKeyId, null, "replacedBy=" + newKeyId);
                audit.append("KEY_REGISTERED", newKeyId, null,
                        "rotatedFrom=" + oldKeyId + ", pub=" + fresh.pubHex()
                                + ", pop=" + popHex);
                return fresh;
            } finally {
                registration.unlock();
            }
        } finally {
            if (oldLock.isHeldByCurrentThread()) {
                oldLock.unlock();
            }
            if (newLock.isHeldByCurrentThread()) {
                newLock.unlock();
            }
        }
    }

    /**
     * 撤销：密钥立即不能参与新会话；历史会话文件中的快照公钥仍可验证历史聚合签名。
     */
    public PublicKeyRecord revoke(String keyId, String reason) {
        ReentrantLock lock = keys.lock(keyId);
        lock.lock();
        try {
            PublicKeyRecord record = keys.findById(keyId)
                    .orElseThrow(() -> new ServiceException(ErrorCode.KEY_NOT_FOUND));
            if (record.status() == KeyStatus.REVOKED) {
                return record;
            }
            PublicKeyRecord revoked = new PublicKeyRecord(
                    record.keyId(), record.owner(), record.pubHex(), KeyStatus.REVOKED,
                    record.version() + 1, record.registeredAt(),
                    System.currentTimeMillis(), record.replacedById(), record.popHex());
            keys.put(revoked);
            audit.append("KEY_REVOKED", keyId, null,
                    reason == null ? "" : reason);
            return revoked;
        } finally {
            lock.unlock();
        }
    }

    public Optional<PublicKeyRecord> get(String keyId) {
        return keys.findById(keyId);
    }

    /**
     * 查询某 keyId 持久化的所有权证明，并即时重验其与当前公钥的匹配性。
     * 旧记录没有证明时返回 popStatus=LEGACY_MISSING、valid=false。
     */
    public Map<String, Object> proofOfPossession(String keyId) {
        PublicKeyRecord record = keys.findById(keyId)
                .orElseThrow(() -> new ServiceException(ErrorCode.KEY_NOT_FOUND,
                        "公钥不存在: " + keyId));
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("keyId", record.keyId());
        view.put("pubHex", record.pubHex());
        view.put("status", record.status().name());
        view.put("popStatus", record.popStatus());
        view.put("popHex", record.popHex());
        boolean valid = false;
        if (record.popHex() != null && !record.popHex().isBlank()) {
            try {
                valid = Schnorr.verifyPop(parsePublicKey(record.pubHex()),
                        Hex.decode(record.popHex()));
            } catch (RuntimeException ex) {
                valid = false;
            }
        }
        view.put("valid", valid);
        return view;
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
