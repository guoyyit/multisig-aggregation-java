package com.github.guoyyit.multisigaggregationjava.tests;

import com.github.guoyyit.multisigaggregationjava.core.Hex;
import com.github.guoyyit.multisigaggregationjava.model.AuditEntry;
import com.github.guoyyit.multisigaggregationjava.model.FailureReason;
import com.github.guoyyit.multisigaggregationjava.model.SessionState;
import com.github.guoyyit.multisigaggregationjava.service.RecoveryService;
import com.github.guoyyit.multisigaggregationjava.signer.LocalSigner;
import com.github.guoyyit.multisigaggregationjava.store.AuditLog;
import com.github.guoyyit.multisigaggregationjava.web.AuditController;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StorageRobustnessTest extends ServiceTestBase {

    @Test
    void staleTempFilesAreCleanedOnStartup(@TempDir Path tempDir) throws IOException {
        Context before = startContext(tempDir);
        Path keysDir;
        Path sessionsDir;
        Path noncesDir;
        Path auditDir;
        try {
            LocalSigner signer = LocalSigner.generate("st-a", before.fileStore());
            before.keyService().register(
                    "st-a", "owner", signer.publicKeyHex(), signer.proofOfPossessionHex());
            keysDir = before.fileStore().keysDir();
            sessionsDir = before.fileStore().sessionsDir();
            noncesDir = before.fileStore().noncesDir();
            auditDir = before.fileStore().auditDir();
        } finally {
            before.close();
        }

        Path orphanKey = keysDir.resolve("orphan.json.tmp-deadbeef");
        Path orphanSession = sessionsDir.resolve("s1.json.tmp-deadbeef");
        Path orphanNonce = noncesDir.resolve("n1.json.tmp-deadbeef");
        Path orphanAudit = auditDir.resolve("events.jsonl.tmp-deadbeef");
        for (Path orphan : List.of(orphanKey, orphanSession, orphanNonce, orphanAudit)) {
            Files.writeString(orphan, "partial-write-garbage", StandardCharsets.UTF_8);
        }

        Context after = startContext(tempDir);
        try {
            for (Path orphan : List.of(orphanKey, orphanSession, orphanNonce, orphanAudit)) {
                assertFalse(Files.exists(orphan),
                        "重启必须清理崩溃残留的临时文件: " + orphan);
            }
            assertTrue(after.keyService().get("st-a").isPresent(),
                    "清理不得误删真实数据");
            try (Stream<Path> files = Files.list(keysDir)) {
                assertTrue(files.noneMatch(p -> p.getFileName().toString().contains(".tmp-")),
                        "数据目录不得残留临时写入的中间文件");
            }
        } finally {
            after.close();
        }
    }

    @Test
    void corruptedAuditTailIsDetectedAndHistoryPreserved(@TempDir Path tempDir)
            throws IOException {
        int completeEvents;
        Path auditFile;
        Context before = startContext(tempDir);
        try {
            LocalSigner signer = LocalSigner.generate("au-a", before.fileStore());
            before.keyService().register(
                    "au-a", "owner", signer.publicKeyHex(), signer.proofOfPossessionHex());
            completeEvents = before.auditLog().entries().size();
            assertTrue(completeEvents > 0);
            auditFile = before.fileStore().auditDir().resolve("events.jsonl");
        } finally {
            before.close();
        }

        Files.writeString(auditFile, "{\"auditId\":\"broken\",\"timestamp\":",
                StandardCharsets.UTF_8, java.nio.file.StandardOpenOption.APPEND);

        Context after = startContext(tempDir);
        try {
            AuditLog.AuditReadResult result = after.auditLog().readAll();
            assertEquals(1, result.corruptedLines(),
                    "崩溃产生的不完整末行必须可检测，不得静默消失");
            long surviving = result.entries().stream()
                    .filter(e -> "KEY_REGISTERED".equals(e.action()) && "au-a".equals(e.keyId()))
                    .count();
            assertEquals(1, surviving, "历史事件必须保持完整可追溯");

            Map<String, Object> view = new AuditController(after.auditLog()).entries();
            assertEquals(1, view.get("corruptedLines"),
                    "审计查询接口必须暴露损坏行计数");
        } finally {
            after.close();
        }
    }

    @Test
    void recoveryAuditsExactlyOnceAcrossRepeatedRecovery(@TempDir Path tempDir) {
        String msg = Hex.encode("idem-recover".getBytes(StandardCharsets.UTF_8));
        Context before = startContext(tempDir);
        try {
            MultisigFlowTest.registerSigners(before, List.of("rc-a", "rc-b"));
            before.sessionService().create("rec-1", msg, List.of("rc-a", "rc-b"), null);
        } finally {
            before.close();
        }

        Context second = startContext(tempDir);
        try {
            assertEquals(SessionState.FAILED_RETRYABLE,
                    second.sessionService().get("rec-1").state());
            assertEquals(FailureReason.RECOVERY_ABORTED,
                    second.sessionService().get("rec-1").failureReason());
            long recoveredAudits = second.auditLog().entries().stream()
                    .filter(e -> "SESSION_RECOVERED".equals(e.action())
                            && "rec-1".equals(e.sessionId()))
                    .count();
            assertEquals(1, recoveredAudits, "恢复动作必须且只审计一次");

            second.spring().getBean(RecoveryService.class).recover();
            long afterManualRerun = second.auditLog().entries().stream()
                    .filter(e -> "SESSION_RECOVERED".equals(e.action())
                            && "rec-1".equals(e.sessionId()))
                    .count();
            assertEquals(1, afterManualRerun, "同一恢复动作重复执行只产生一次审计记录");
        } finally {
            second.close();
        }

        Context third = startContext(tempDir);
        try {
            long recoveredAudits = third.auditLog().entries().stream()
                    .filter(e -> "SESSION_RECOVERED".equals(e.action())
                            && "rec-1".equals(e.sessionId()))
                    .count();
            assertEquals(1, recoveredAudits, "反复重启不得积累重复恢复审计");
            long recoveryComplete = third.auditLog().entries().stream()
                    .filter(e -> "RECOVERY_COMPLETE".equals(e.action()))
                    .count();
            assertEquals(1, recoveryComplete);
        } finally {
            third.close();
        }
    }
}
