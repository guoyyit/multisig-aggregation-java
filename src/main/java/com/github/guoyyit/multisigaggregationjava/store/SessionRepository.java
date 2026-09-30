package com.github.guoyyit.multisigaggregationjava.store;

import com.fasterxml.jackson.core.type.TypeReference;
import com.github.guoyyit.multisigaggregationjava.core.Hex;
import com.github.guoyyit.multisigaggregationjava.model.SessionRecord;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Stream;

@Component
public class SessionRepository {

    public record UsedNonce(String sessionId, String nonceHex, long createdAt) {
    }

    private final FileStore store;
    private final ConcurrentHashMap<String, ReentrantLock> sessionLocks = new ConcurrentHashMap<>();
    private final ReentrantLock nonceLedgerLock = new ReentrantLock();

    public SessionRepository(FileStore store) {
        this.store = store;
    }

    public ReentrantLock lock(String sessionId) {
        return sessionLocks.computeIfAbsent(sessionId, ignored -> new ReentrantLock());
    }

    public ReentrantLock nonceLedgerLock() {
        return nonceLedgerLock;
    }

    public SessionRecord save(SessionRecord session) {
        store.atomicWriteJson(sessionFile(session.sessionId()), session);
        return session;
    }

    public Optional<SessionRecord> findById(String sessionId) {
        return Optional.ofNullable(store.readJson(sessionFile(sessionId), SessionRecord.class));
    }

    public List<SessionRecord> findAll() {
        List<SessionRecord> records = new ArrayList<>();
        try (Stream<Path> files = Files.list(store.sessionsDir())) {
            files.filter(p -> p.getFileName().toString().endsWith(".json")).forEach(path -> {
                SessionRecord record = store.readJson(path, SessionRecord.class);
                if (record != null) {
                    records.add(record);
                }
            });
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        return List.copyOf(records);
    }

    /**
     * 记录某签名方使用过的随机数点。返回 false 表示同一随机数点曾出现在另一会话中（重用）。
     */
    public boolean rememberNonce(String keyId, String sessionId, String nonceHex) {
        Map<String, UsedNonce> ledger = loadLedger(keyId);
        String fingerprint = fingerprintNonce(nonceHex);
        UsedNonce existing = ledger.get(fingerprint);
        if (existing != null && !existing.sessionId().equals(sessionId)) {
            return false;
        }
        if (existing == null) {
            ledger.put(fingerprint, new UsedNonce(sessionId, nonceHex, System.currentTimeMillis()));
            store.atomicWriteJson(nonceFile(keyId), ledger);
        }
        return true;
    }

    public boolean isNonceKnown(String keyId, String nonceHex) {
        return loadLedger(keyId).containsKey(fingerprintNonce(nonceHex));
    }

    public Map<String, UsedNonce> loadLedger(String keyId) {
        Path file = nonceFile(keyId);
        if (!Files.exists(file)) {
            return new LinkedHashMap<>();
        }
        Map<String, UsedNonce> value = store.mapper().convertValue(
                store.readJson(file, Map.class), new TypeReference<LinkedHashMap<String, UsedNonce>>() {
                });
        return value == null ? new LinkedHashMap<>() : value;
    }

    private String fingerprintNonce(String nonceHex) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Hex.encode(digest.digest(Hex.decode(nonceHex)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private Path sessionFile(String sessionId) {
        if (sessionId == null || !sessionId.matches("[A-Za-z0-9._-]{1,128}")) {
            throw new IllegalArgumentException("非法 sessionId");
        }
        return store.sessionsDir().resolve(sessionId + ".json");
    }

    private Path nonceFile(String keyId) {
        if (keyId == null || !keyId.matches("[A-Za-z0-9._-]{1,128}")) {
            throw new IllegalArgumentException("非法 keyId");
        }
        return store.noncesDir().resolve(keyId + ".json");
    }
}
