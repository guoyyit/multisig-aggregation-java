package com.github.guoyyit.multisigaggregationjava.store;

import com.github.guoyyit.multisigaggregationjava.domain.RegisteredKey;
import com.github.guoyyit.multisigaggregationjava.domain.SignSession;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Persists all registrations, proofs of possession, sessions and nonce-use
 * records. Mutations run under a global write lock and are flushed atomically
 * (write-temp + move) before the operation returns, so concurrent writers can
 * never overwrite each other and a crash never leaves a torn state file.
 */
public class PersistentStateStore {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Path stateFile;
    private final Path tempFile;
    private final ReadWriteLock lock = new ReentrantReadWriteLock();
    private volatile StateData data;

    public PersistentStateStore(Path stateFile) {
        this.stateFile = stateFile;
        this.tempFile = stateFile.resolveSibling(stateFile.getFileName() + ".tmp");
        try {
            Path parent = stateFile.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("cannot create state directory", e);
        }
    }

    /** Load or initialize state; marks in-flight sessions for restart recovery. */
    public StateData load() {
        lock.writeLock().lock();
        try {
            if (data != null) {
                return data;
            }
            if (Files.exists(stateFile)) {
                try {
                    data = MAPPER.readValue(Files.readAllBytes(stateFile), StateData.class);
                } catch (IOException e) {
                    throw new UncheckedIOException("cannot read state file " + stateFile, e);
                }
            } else {
                data = StateData.empty();
                persistLocked();
            }
            return data;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public ReadWriteLock lock() {
        return lock;
    }

    public void persist(StateData data) {
        lock.writeLock().lock();
        try {
            this.data = data;
            persistLocked();
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** Must be called while holding the write lock. */
    public void persistLocked() {
        try {
            byte[] bytes = MAPPER.writerWithDefaultPrettyPrinter().writeValueAsBytes(requireData());
            Files.write(tempFile, bytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            try {
                Files.move(tempFile, stateFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (IOException atomicFailure) {
                Files.move(tempFile, stateFile, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("cannot persist state", e);
        }
    }

    public List<RegisteredKey> allKeys() {
        lock.readLock().lock();
        try {
            return new ArrayList<>(requireData().keys().values());
        } finally {
            lock.readLock().unlock();
        }
    }

    public RegisteredKey getKey(String keyId) {
        lock.readLock().lock();
        try {
            return requireData().keys().get(keyId);
        } finally {
            lock.readLock().unlock();
        }
    }

    public void putKey(RegisteredKey key) {
        lock.writeLock().lock();
        try {
            requireData().keys().put(key.keyId(), key);
            persistLocked();
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void putSession(SignSession session) {
        lock.writeLock().lock();
        try {
            requireData().sessions().put(session.getSessionId(), session);
            persistLocked();
        } finally {
            lock.writeLock().unlock();
        }
    }

    public SignSession getSession(String sessionId) {
        lock.readLock().lock();
        try {
            return requireData().sessions().get(sessionId);
        } finally {
            lock.readLock().unlock();
        }
    }

    public List<SignSession> allSessions() {
        lock.readLock().lock();
        try {
            return new ArrayList<>(requireData().sessions().values());
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Record that a nonce tuple was committed in a session/round.
     *
     * @return previous tuple hex if this session/round/key already committed
     */
    public String putNonceTuple(String sessionId, int round, String keyId, String tupleHex) {
        lock.writeLock().lock();
        try {
            Map<Integer, Map<String, String>> perSession =
                    requireData().usedNonceTuples().computeIfAbsent(sessionId, id -> new java.util.LinkedHashMap<>());
            Map<String, String> perRound = perSession.computeIfAbsent(round, r -> new java.util.LinkedHashMap<>());
            String previous = perRound.put(keyId, tupleHex);
            persistLocked();
            return previous;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Register a (R1,R2,m) tuple as consumed by a partial signature.
     *
     * @return the previous session/round reference if the same tuple was already
     *         used against another message/session (cross-message reuse)
     */
    public String markConsumedPartial(String tupleKey, String sessionRoundRef) {
        lock.writeLock().lock();
        try {
            String existing = requireData().consumedPartialKey().putIfAbsent(tupleKey, sessionRoundRef);
            if (existing == null) {
                persistLocked();
            }
            return existing;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Search every session/round/key slot for a previously committed public
     * nonce tuple, excluding one exact slot (used for idempotent resubmission).
     * Returns "sessionId#round/keyId" when found, otherwise {@code null}.
     */
    public String findNonceTupleOtherSlot(String tupleHex, String sessionId, int round, String keyId) {
        lock.readLock().lock();
        try {
            for (Map.Entry<String, Map<Integer, Map<String, String>>> sessionEntry
                    : requireData().usedNonceTuples().entrySet()) {
                for (Map.Entry<Integer, Map<String, String>> roundEntry : sessionEntry.getValue().entrySet()) {
                    for (Map.Entry<String, String> keyEntry : roundEntry.getValue().entrySet()) {
                        if (sessionEntry.getKey().equals(sessionId)
                                && roundEntry.getKey() == round
                                && keyEntry.getKey().equals(keyId)) {
                            continue;
                        }
                        if (keyEntry.getValue().equals(tupleHex)) {
                            return sessionEntry.getKey() + "#" + roundEntry.getKey() + "/" + keyEntry.getKey();
                        }
                    }
                }
            }
            return null;
        } finally {
            lock.readLock().unlock();
        }
    }

    private StateData requireData() {
        if (data == null) {
            throw new IllegalStateException("state not loaded; call load() first");
        }
        return data;
    }
}
