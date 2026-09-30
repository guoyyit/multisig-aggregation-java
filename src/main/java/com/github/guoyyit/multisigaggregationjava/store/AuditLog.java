package com.github.guoyyit.multisigaggregationjava.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.multisigaggregationjava.model.AuditEntry;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Component
public class AuditLog {

    private static final ObjectMapper COMPACT = new ObjectMapper();

    private final FileStore store;
    private final Object appendLock = new Object();

    public AuditLog(FileStore store) {
        this.store = store;
    }

    public void append(String action, String keyId, String sessionId, String detail) {
        AuditEntry entry = new AuditEntry(
                UUID.randomUUID().toString(),
                System.currentTimeMillis(),
                action,
                keyId == null ? "" : keyId,
                sessionId == null ? "" : sessionId,
                detail == null ? "" : detail);
        try {
            String line = COMPACT.writeValueAsString(entry);
            synchronized (appendLock) {
                store.appendLine(store.auditDir().resolve("events.jsonl"), line);
            }
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    public List<AuditEntry> entries() {
        Path file = store.auditDir().resolve("events.jsonl");
        if (!Files.exists(file)) {
            return List.of();
        }
        List<AuditEntry> entries = new ArrayList<>();
        synchronized (appendLock) {
            try {
                for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                    String trimmed = line.trim();
                    if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) {
                        continue;
                    }
                    try {
                        entries.add(COMPACT.readValue(trimmed, AuditEntry.class));
                    } catch (IOException truncatedTrailingRecord) {
                        // 崩溃时可能残留未刷盘的末行；忽略该不完整记录，已落盘记录仍可追溯。
                    }
                }
            } catch (IOException ex) {
                throw new UncheckedIOException(ex);
            }
        }
        return List.copyOf(entries);
    }
}
