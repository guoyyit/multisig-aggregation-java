package com.github.guoyyit.multisigaggregationjava.tests;

import com.github.guoyyit.multisigaggregationjava.core.Hex;
import com.github.guoyyit.multisigaggregationjava.model.AuditEntry;
import com.github.guoyyit.multisigaggregationjava.model.KeyStatus;
import com.github.guoyyit.multisigaggregationjava.model.ProofStatus;
import com.github.guoyyit.multisigaggregationjava.model.PublicKeyRecord;
import com.github.guoyyit.multisigaggregationjava.signer.LocalSigner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProofPersistenceTest extends ServiceTestBase {

    @Test
    void proofPersistsAcrossRegisterRotateRevokeAndRestartAndReverifies(@TempDir Path tempDir) {
        Context before = startContext(tempDir);
        try {
            List<LocalSigner> signers = MultisigFlowTest.registerSigners(
                    before, List.of("a", "b"));
            LocalSigner b2 = LocalSigner.generate("b2", before.fileStore());
            String b2Pop = b2.proofOfPossessionHex();
            before.keyService().rotate("b", "b2", b2.publicKeyHex(),
                    b2Pop);
            before.keyService().revoke("a", null);

            PublicKeyRecord active = before.keyService().get("b2").orElseThrow();
            assertEquals(ProofStatus.PRESENT, active.proofStatus());
            assertEquals(b2Pop, active.popHex());
            assertTrue(before.keyService().verifyStoredProof("b2").valid());

            PublicKeyRecord superseded = before.keyService().get("b").orElseThrow();
            assertEquals(ProofStatus.PRESENT, superseded.proofStatus());
            assertTrue(before.keyService().verifyStoredProof("b").valid());

            PublicKeyRecord revoked = before.keyService().get("a").orElseThrow();
            assertEquals(KeyStatus.REVOKED, revoked.status());
            assertEquals(ProofStatus.PRESENT, revoked.proofStatus());
            assertTrue(before.keyService().verifyStoredProof("a").valid());

            for (AuditEntry entry : before.auditLog().entries()) {
                if ("KEY_REGISTERED".equals(entry.action())) {
                    assertTrue(entry.detail().contains("proofStatus=PRESENT"));
                    assertTrue(entry.detail().contains("popFingerprint="));
                    assertFalse(entry.detail().contains("secret"));
                }
            }
        } finally {
            before.close();
        }

        Context after = startContext(tempDir);
        try {
            for (String keyId : List.of("a", "b", "b2")) {
                PublicKeyRecord reloaded = after.keyService().get(keyId).orElseThrow();
                assertEquals(ProofStatus.PRESENT, reloaded.proofStatus());
                assertNotNull(reloaded.popHex());
                assertTrue(after.keyService().verifyStoredProof(keyId).valid(),
                        "重启后仍可重新验证 " + keyId + " 的所有权证明");
            }

            String msg = Hex.encode("post-restart".getBytes(StandardCharsets.UTF_8));
            LocalSigner b2 = LocalSigner.load("b2", after.fileStore());
            var session = after.sessionService()
                    .create("proof-sess", msg, List.of("b2"), null);
            assertEquals("proof-sess",
                    MultisigFlowTest.runProtocol(after, List.of(b2), session).sessionId());
        } finally {
            after.close();
        }
    }

    @Test
    void legacyRegistrationWithoutProofLoadsWithExplainableStatusAndStillWorks(
            @TempDir Path tempDir) throws Exception {
        // 写入升级前格式的注册记录（无 popHex / proofStatus 字段）。
        Path dataDir = tempDir.resolve("data");
        Files.createDirectories(dataDir.resolve("keys"));
        LocalSigner legacy = LocalSigner.generate("legacy",
                proofStore(dataDir));
        String legacyJson = """
                {
                  "keyId" : "legacy",
                  "owner" : "legacy-owner",
                  "pubHex" : "%s",
                  "status" : "ACTIVE",
                  "version" : 1,
                  "registeredAt" : 1,
                  "revokedAt" : 0,
                  "replacedById" : null
                }
                """.formatted(legacy.publicKeyHex());
        Files.writeString(dataDir.resolve("keys").resolve("legacy.json"), legacyJson);

        Context after = startContext(tempDir);
        try {
            PublicKeyRecord record = after.keyService().get("legacy").orElseThrow();
            assertEquals(KeyStatus.ACTIVE, record.status());
            assertEquals(ProofStatus.LEGACY_MISSING, record.proofStatus(),
                    "旧记录必须有明确可解释的证明状态");

            var verification = after.keyService().verifyStoredProof("legacy");
            assertEquals(ProofStatus.LEGACY_MISSING, verification.proofStatus());
            assertFalse(verification.valid());

            String msg = Hex.encode("legacy-ok".getBytes(StandardCharsets.UTF_8));
            var session = after.sessionService()
                    .create("legacy-sess", msg, List.of("legacy"), null);
            var completed = MultisigFlowTest.runProtocol(after, List.of(legacy), session);
            assertTrue(after.aggregation().verifyAggregate(
                    msg, completed.aggregatePubHex(), completed.aggregateSignatureHex()),
                    "旧记录保持可参与新会话，历史验证不受影响");
        } finally {
            after.close();
        }
    }

    private static com.github.guoyyit.multisigaggregationjava.store.FileStore proofStore(
            Path dataDir) {
        var properties = new com.github.guoyyit.multisigaggregationjava.config.ServiceProperties();
        properties.setStoreDir(dataDir.toString());
        var store = new com.github.guoyyit.multisigaggregationjava.store.FileStore(properties);
        store.initialize();
        return store;
    }
}
