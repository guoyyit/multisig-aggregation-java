package com.github.guoyyit.multisigaggregationjava.tests;

import com.github.guoyyit.multisigaggregationjava.core.Hex;
import com.github.guoyyit.multisigaggregationjava.model.AuditEntry;
import com.github.guoyyit.multisigaggregationjava.model.KeyStatus;
import com.github.guoyyit.multisigaggregationjava.model.SessionRecord;
import com.github.guoyyit.multisigaggregationjava.model.SessionState;
import com.github.guoyyit.multisigaggregationjava.signer.LocalSigner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PopPersistenceTest extends ServiceTestBase {

    @Test
    void registeredProofSurvivesRestartAndReverifies(@TempDir Path tempDir) {
        LocalSigner signer;
        String pop;

        Context before = startContext(tempDir);
        try {
            signer = LocalSigner.generate("pop-a", before.fileStore());
            pop = signer.proofOfPossessionHex();
            before.keyService().register("pop-a", "owner-a", signer.publicKeyHex(), pop);
        } finally {
            before.close();
        }

        Context after = startContext(tempDir);
        try {
            Map<String, Object> view = after.keyService().proofOfPossession("pop-a");
            assertEquals("PRESENT", view.get("popStatus"));
            assertEquals(pop, view.get("popHex"), "重启后必须能取回历史上提交的所有权证明");
            assertEquals(Boolean.TRUE, view.get("valid"), "取回的证明必须能重新验证对应公钥");
            assertEquals("PRESENT", after.keyService().get("pop-a").orElseThrow().popStatus());
        } finally {
            after.close();
        }
    }

    @Test
    void rotatedAndRevokedKeysKeepTheirProofs(@TempDir Path tempDir) {
        LocalSigner first;
        LocalSigner second;
        String firstPop;
        String secondPop;

        Context before = startContext(tempDir);
        try {
            first = LocalSigner.generate("rot-a", before.fileStore());
            second = LocalSigner.generate("rot-b", before.fileStore());
            firstPop = first.proofOfPossessionHex();
            secondPop = second.proofOfPossessionHex();
            before.keyService().register("rot-a", "owner", first.publicKeyHex(), firstPop);
            before.keyService().rotate("rot-a", "rot-b", second.publicKeyHex(), secondPop);
            before.keyService().revoke("rot-b", "compromised");
        } finally {
            before.close();
        }

        Context after = startContext(tempDir);
        try {
            Map<String, Object> superseded = after.keyService().proofOfPossession("rot-a");
            assertEquals(KeyStatus.SUPERSEDED.name(), superseded.get("status"));
            assertEquals(firstPop, superseded.get("popHex"), "被轮换密钥的证明必须保留可查");
            assertEquals(Boolean.TRUE, superseded.get("valid"));

            Map<String, Object> revoked = after.keyService().proofOfPossession("rot-b");
            assertEquals(KeyStatus.REVOKED.name(), revoked.get("status"));
            assertEquals(secondPop, revoked.get("popHex"), "被撤销密钥的证明必须保留可查");
            assertEquals(Boolean.TRUE, revoked.get("valid"));
        } finally {
            after.close();
        }
    }

    @Test
    void registrationAndRotationAuditsCarryProofButNoSecret(@TempDir Path tempDir) {
        Context context = startContext(tempDir);
        try {
            LocalSigner first = LocalSigner.generate("aud-a", context.fileStore());
            LocalSigner second = LocalSigner.generate("aud-b", context.fileStore());
            String firstPop = first.proofOfPossessionHex();
            String secondPop = second.proofOfPossessionHex();
            context.keyService().register(
                    "aud-a", "owner", first.publicKeyHex(), firstPop);
            context.keyService().rotate(
                    "aud-a", "aud-b", second.publicKeyHex(), secondPop);

            List<AuditEntry> entries = context.auditLog().entries();
            AuditEntry registered = entries.stream()
                    .filter(e -> "KEY_REGISTERED".equals(e.action()) && "aud-a".equals(e.keyId()))
                    .findFirst().orElseThrow();
            assertTrue(registered.detail().contains("pop=" + firstPop),
                    "注册审计必须携带当时提交的证明以便事后核对");
            AuditEntry rotatedRegister = entries.stream()
                    .filter(e -> "KEY_REGISTERED".equals(e.action()) && "aud-b".equals(e.keyId()))
                    .findFirst().orElseThrow();
            assertTrue(rotatedRegister.detail().contains("pop=" + secondPop),
                    "轮换产生的新密钥注册审计必须携带证明");
            assertTrue(entries.stream().anyMatch(
                    e -> "KEY_ROTATED".equals(e.action()) && "aud-a".equals(e.keyId())));
            for (AuditEntry entry : entries) {
                assertFalse(entry.detail().contains("secret"),
                        "审计不得包含私钥材料");
            }
        } finally {
            context.close();
        }
    }

    @Test
    void legacyRecordWithoutProofLoadsAndStaysUsable(@TempDir Path tempDir) throws IOException {
        String msg = Hex.encode("legacy-msg".getBytes(StandardCharsets.UTF_8));
        LocalSigner legacy;
        LocalSigner modern;
        String legacyPub;

        Context setup = startContext(tempDir);
        try {
            legacy = LocalSigner.generate("legacy", setup.fileStore());
            modern = LocalSigner.generate("modern", setup.fileStore());
            legacyPub = legacy.publicKeyHex();
            writeLegacyKeyRecord(setup.fileStore().keysDir(), "legacy", legacyPub);
            setup.keyService().register(
                    "modern", "owner", modern.publicKeyHex(), modern.proofOfPossessionHex());
        } finally {
            setup.close();
        }

        Context upgraded = startContext(tempDir);
        String legacyAggregate;
        String legacySignature;
        try {
            var legacyRecord = upgraded.keyService().get("legacy").orElseThrow();
            assertEquals(KeyStatus.ACTIVE, legacyRecord.status(), "旧记录必须正常加载且不丢数据");
            assertEquals("LEGACY_MISSING", legacyRecord.popStatus(),
                    "旧记录的证明缺失必须是明确可解释的状态");

            Map<String, Object> pop = upgraded.keyService().proofOfPossession("legacy");
            assertEquals("LEGACY_MISSING", pop.get("popStatus"));
            assertEquals(Boolean.FALSE, pop.get("valid"));
            assertNotNull(upgraded.keyService().proofOfPossession("modern").get("popHex"));

            SessionRecord session = upgraded.sessionService()
                    .create("legacy-session", msg, List.of("legacy", "modern"), null);
            SessionRecord completed = MultisigFlowTest.runProtocol(
                    upgraded, List.of(legacy, modern), session);
            assertEquals(SessionState.COMPLETED, completed.state(),
                    "旧记录必须保持可参与新会话");
            legacyAggregate = completed.aggregatePubHex();
            legacySignature = completed.aggregateSignatureHex();
        } finally {
            upgraded.close();
        }

        Context restarted = startContext(tempDir);
        try {
            assertTrue(restarted.aggregation().verifyAggregate(msg, legacyAggregate, legacySignature),
                    "重启后历史签名验证不受影响");
            assertEquals("LEGACY_MISSING",
                    restarted.keyService().get("legacy").orElseThrow().popStatus());
        } finally {
            restarted.close();
        }
    }

    /**
     * 以升级前的旧格式（无 popHex 字段）直接写一条公钥记录，模拟历史数据。
     */
    private static void writeLegacyKeyRecord(Path keysDir, String keyId, String pubHex)
            throws IOException {
        String json = "{\n"
                + "  \"keyId\" : \"" + keyId + "\",\n"
                + "  \"owner\" : \"legacy-owner\",\n"
                + "  \"pubHex\" : \"" + pubHex + "\",\n"
                + "  \"status\" : \"ACTIVE\",\n"
                + "  \"version\" : 1,\n"
                + "  \"registeredAt\" : 1700000000000,\n"
                + "  \"revokedAt\" : 0,\n"
                + "  \"replacedById\" : null\n"
                + "}";
        Files.writeString(keysDir.resolve(keyId + ".json"), json, StandardCharsets.UTF_8);
    }
}
