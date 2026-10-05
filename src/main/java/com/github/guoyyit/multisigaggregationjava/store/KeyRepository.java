package com.github.guoyyit.multisigaggregationjava.store;

import com.github.guoyyit.multisigaggregationjava.model.KeyStatus;
import com.github.guoyyit.multisigaggregationjava.model.PublicKeyRecord;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Stream;

@Component
public class KeyRepository {

    private final FileStore store;
    private final ConcurrentHashMap<String, ReentrantLock> keyLocks = new ConcurrentHashMap<>();
    private final ReentrantLock registrationLock = new ReentrantLock();

    public KeyRepository(FileStore store) {
        this.store = store;
    }

    /**
     * 同一 keyId 的读-改-写必须串行，避免并发注册/撤销相互覆盖。
     */
    public ReentrantLock lock(String keyId) {
        return keyLocks.computeIfAbsent(keyId, ignored -> new ReentrantLock());
    }

    /**
     * 全局注册锁：保证“检查公钥唯一性 + 写入新记录”跨 keyId 原子执行，
     * 同一公钥材料以不同 keyId 并发注册时至多一个成功。
     */
    public ReentrantLock registrationLock() {
        return registrationLock;
    }

    public List<PublicKeyRecord> findAll() {
        List<PublicKeyRecord> records = new ArrayList<>();
        try (Stream<Path> files = Files.list(store.keysDir())) {
            files.filter(p -> p.getFileName().toString().endsWith(".json")).forEach(path -> {
                PublicKeyRecord record = store.readJson(path, PublicKeyRecord.class);
                if (record != null) {
                    records.add(record);
                }
            });
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        return List.copyOf(records);
    }

    public Optional<PublicKeyRecord> findById(String keyId) {
        return Optional.ofNullable(store.readJson(keyFile(keyId), PublicKeyRecord.class));
    }

    public List<PublicKeyRecord> findByStatus(KeyStatus status) {
        return findAll().stream().filter(record -> record.status() == status).toList();
    }

    public void put(PublicKeyRecord record) {
        store.atomicWriteJson(keyFile(record.keyId()), record);
    }

    private Path keyFile(String keyId) {
        if (keyId == null || !keyId.matches("[A-Za-z0-9._-]{1,128}")) {
            throw new IllegalArgumentException("非法 keyId");
        }
        return store.keysDir().resolve(keyId + ".json");
    }
}
