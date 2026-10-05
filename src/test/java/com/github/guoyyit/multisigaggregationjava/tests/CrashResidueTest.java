package com.github.guoyyit.multisigaggregationjava.tests;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CrashResidueTest extends ServiceTestBase {

    @Test
    void leftoverTemporaryFilesAreCleanedOnStartupAndDoNotAccumulate(
            @TempDir Path tempDir) throws Exception {
        Path dataDir = tempDir.resolve("data");
        Files.createDirectories(dataDir.resolve("keys"));
        Files.createDirectories(dataDir.resolve("sessions"));
        Files.createDirectories(dataDir.resolve("audit"));
        Files.writeString(dataDir.resolve("keys").resolve("k1.tmp-abcd"), "{}");
        Files.writeString(dataDir.resolve("sessions").resolve("s2.tmp-dead"), "{partial");

        Context first = startContext(tempDir);
        try {
            assertFalse(Files.exists(dataDir.resolve("keys").resolve("k1.tmp-abcd")),
                    "启动必须自动清理崩溃残留临时文件");
            assertFalse(Files.exists(dataDir.resolve("sessions").resolve("s2.tmp-dead")));

            // 正常注册后再次重启，不得出现垃圾文件积累。
            MultisigFlowTest.registerSigners(first, java.util.List.of("clean-a"));
            Files.writeString(dataDir.resolve("keys").resolve("k3.tmp-eeee"), "x");
        } finally {
            first.close();
        }

        Context second = startContext(tempDir);
        try (var walk = Files.walk(dataDir)) {
            boolean anyTemp = walk.anyMatch(path -> path.getFileName().toString()
                    .contains(".tmp-"));
            assertFalse(anyTemp, "反复崩溃与重启不得积累临时文件");
        }
        try {
            assertTrue(second.keyService().get("clean-a").isPresent(),
                    "正式数据不受清理影响");
        } finally {
            second.close();
        }
    }

    @Test
    void truncatedAuditTrailingLineIsReportedWhileHistoryStaysIntact(
            @TempDir Path tempDir) throws Exception {
        Context context = startContext(tempDir);
        try {
            MultisigFlowTest.registerSigners(context, java.util.List.of("aud-a"));
        } finally {
            context.close();
        }

        Path auditFile = tempDir.resolve("data").resolve("audit").resolve("events.jsonl");
        long completeBefore;
        try (var lines = Files.lines(auditFile, StandardCharsets.UTF_8)) {
            completeBefore = lines.count();
        }
        // 模拟崩溃：末尾追加一行写了一半、没有换行结束的 JSON。
        Files.writeString(auditFile,
                "{\"auditId\":\"x\",\"timestamp\":1,\"action\":\"TRUNC",
                java.nio.file.StandardOpenOption.APPEND);

        Context after = startContext(tempDir);
        try {
            var read = after.auditLog().read();
            assertEquals(1, read.truncatedTrailingLines(),
                    "不完整末行必须被检测并计数，不得静默消失");
            assertEquals(completeBefore, read.entries().size(),
                    "历史完整事件必须保持完整可追溯");

            // 完整审计写入与读取在检测到残留后仍正常工作。
            after.keyService().revoke("aud-a", null);
            var readAgain = after.auditLog().read();
            assertEquals(completeBefore + 1, readAgain.entries().size());
            assertEquals(1, readAgain.truncatedTrailingLines());
        } finally {
            after.close();
        }
    }
}
