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

    /**
     * 审计读取结果：完整事件 + 因崩溃截断而无法解析的行数。
     * corruptedLines &gt; 0 是一个可检测的标记，调用方据此可知日志曾受损，
     * 损坏行不会被静默丢弃。
     */
    public record AuditReadResult(List<AuditEntry> entries, int corruptedLines) {
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
        return readAll().entries();
    }

    public AuditReadResult readAll() {
        Path file = store.auditDir().resolve("events.jsonl");
        if (!Files.exists(file)) {
            return new AuditReadResult(List.of(), 0);
        }
        List<AuditEntry> entries = new ArrayList<>();
        int corrupted = 0;
        synchronized (appendLock) {
            try {
                for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                    String trimmed = line.trim();
                    if (trimmed.isEmpty()) {
                        continue;
                    }
                    if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) {
                        corrupted++;
                        continue;
                    }
                    try {
                        entries.add(COMPACT.readValue(trimmed, AuditEntry.class));
                    } catch (IOException truncatedTrailingRecord) {
                        // 崩溃时可能残留未刷盘的末行：不计入事件流，但计入 corruptedLines，
                        // 调用方可以检测到日志曾受损，损坏行不会被静默丢弃。
                        corrupted++;
                    }
                }
            } catch (IOException ex) {
                throw new UncheckedIOException(ex);
            }
        }
        return new AuditReadResult(List.copyOf(entries), corrupted);
    }
}
