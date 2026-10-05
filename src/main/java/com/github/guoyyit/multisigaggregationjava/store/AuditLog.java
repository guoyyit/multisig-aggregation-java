package com.github.guoyyit.multisigaggregationjava.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.multisigaggregationjava.model.AuditEntry;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
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
        Path file = store.auditDir().resolve("events.jsonl");
        try {
            String line = COMPACT.writeValueAsString(entry);
            synchronized (appendLock) {
                quarantineTrailingPartialLine(file);
                store.appendLine(file, line);
            }
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    /**
     * 若日志末尾存在没有换行结尾的半行（崩溃残留），把该残行原样移入
     * {@code audit/quarantine/} 隔离保存并截断主日志，使新事件从干净行边界开始。
     * 残行不会被静默删除；{@link #read()} 仍会把隔离数量作为可检测标记返回。
     */
    private void quarantineTrailingPartialLine(Path file) throws IOException {
        if (!Files.exists(file) || Files.size(file) == 0) {
            return;
        }
        byte[] bytes = Files.readAllBytes(file);
        if (bytes[bytes.length - 1] == (byte) '\n') {
            return;
        }
        int split = bytes.length;
        for (int index = bytes.length - 1; index >= 0; index--) {
            if (bytes[index] == (byte) '\n') {
                split = index + 1;
                break;
            }
            if (index == 0) {
                split = 0;
            }
        }
        byte[] partial = java.util.Arrays.copyOfRange(bytes, split, bytes.length);
        byte[] intact = java.util.Arrays.copyOfRange(bytes, 0, split);

        Path quarantineDir = store.auditQuarantineDir();
        Files.createDirectories(quarantineDir);
        Path quarantineFile = quarantineDir.resolve(
                "events-partial-" + System.currentTimeMillis() + "-" + UUID.randomUUID() + ".raw");
        Files.write(quarantineFile, partial,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE);
        Files.write(file, intact,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE);
    }

    public List<AuditEntry> entries() {
        return read().entries();
    }

    /**
     * 读取审计日志并检测崩溃产生的不完整末行。历史完整事件全部保留可追溯；
     * 残行计入 {@code truncatedTrailingLines}（含已隔离到 quarantine 目录的原始残行），
     * 不静默消失。下次写入前残行会被移入 {@code audit/quarantine/*.raw} 隔离。
     */
    public AuditRead read() {
        Path file = store.auditDir().resolve("events.jsonl");
        List<AuditEntry> entries = new ArrayList<>();
        int truncated = countQuarantinedPartials();
        synchronized (appendLock) {
            if (Files.exists(file)) {
                try {
                    List<String> rawLines = Files.readAllLines(file, StandardCharsets.UTF_8);
                    for (int index = 0; index < rawLines.size(); index++) {
                        String trimmed = rawLines.get(index).trim();
                        if (trimmed.isEmpty()) {
                            continue;
                        }
                        AuditEntry parsed = null;
                        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
                            try {
                                parsed = COMPACT.readValue(trimmed, AuditEntry.class);
                            } catch (IOException parseFailure) {
                                parsed = null;
                            }
                        }
                        if (parsed != null) {
                            entries.add(parsed);
                        } else if (index == rawLines.size() - 1) {
                            truncated++;
                        } else {
                            throw new UncheckedIOException(new IOException(
                                    "审计日志存在非末尾的损坏行，已拒绝读取以保留证据: " + trimmed));
                        }
                    }
                } catch (IOException ex) {
                    throw new UncheckedIOException(ex);
                }
            }
        }
        return new AuditRead(List.copyOf(entries), truncated);
    }

    private int countQuarantinedPartials() {
        Path quarantineDir = store.auditQuarantineDir();
        if (!Files.exists(quarantineDir)) {
            return 0;
        }
        try {
            try (var list = Files.list(quarantineDir)) {
                return (int) list.filter(p -> p.getFileName().toString().endsWith(".raw")).count();
            }
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    public record AuditRead(List<AuditEntry> entries, int truncatedTrailingLines) {
    }
}
