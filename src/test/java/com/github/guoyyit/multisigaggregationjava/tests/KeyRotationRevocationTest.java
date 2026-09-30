package com.github.guoyyit.multisigaggregationjava.tests;

import com.github.guoyyit.multisigaggregationjava.core.ErrorCode;
import com.github.guoyyit.multisigaggregationjava.core.Hex;
import com.github.guoyyit.multisigaggregationjava.core.ServiceException;
import com.github.guoyyit.multisigaggregationjava.model.KeyStatus;
import com.github.guoyyit.multisigaggregationjava.model.SessionRecord;
import com.github.guoyyit.multisigaggregationjava.model.SessionState;
import com.github.guoyyit.multisigaggregationjava.signer.LocalSigner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyRotationRevocationTest extends ServiceTestBase {

    @Test
    void revokedKeyCannotJoinNewSessionButHistoryStillVerifies(@TempDir Path tempDir) {
        Context context = startContext(tempDir);
        try {
            List<LocalSigner> signers = MultisigFlowTest.registerSigners(
                    context, List.of("a", "b"));
            String msg = Hex.encode("history".getBytes(StandardCharsets.UTF_8));
            SessionRecord session = context.sessionService()
                    .create("rot-1", msg, List.of("a", "b"), null);
            SessionRecord completed = MultisigFlowTest.runProtocol(context, signers, session);
            String oldAggregate = completed.aggregatePubHex();
            String oldSignature = completed.aggregateSignatureHex();

            context.keyService().revoke("b", "leaving company");
            assertEquals(KeyStatus.REVOKED,
                    context.keyService().get("b").orElseThrow().status());

            ServiceException ex = assertThrows(ServiceException.class,
                    () -> context.sessionService()
                            .create("rot-2", msg, List.of("a", "b"), null));
            assertEquals(ErrorCode.KEY_REVOKED, ex.errorCode());

            assertTrue(context.aggregation().verifyAggregate(msg, oldAggregate, oldSignature),
                    "撤销不影响历史聚合签名的可验证性");
            assertTrue(context.sessionService().get("rot-1").state() == SessionState.COMPLETED);
        } finally {
            context.close();
        }
    }

    @Test
    void rotatedKeyProducesNewAggregateKeyForNewSessions(@TempDir Path tempDir) {
        Context context = startContext(tempDir);
        try {
            List<LocalSigner> signers = MultisigFlowTest.registerSigners(
                    context, List.of("a", "b"));
            String oldAggregate = context.aggregation()
                    .aggregatePublicHex(List.of("a", "b"));

            LocalSigner b2 = LocalSigner.generate("b2", context.fileStore());
            context.keyService().rotate(
                    "b", "b2", b2.publicKeyHex(), b2.proofOfPossessionHex());

            assertEquals(KeyStatus.SUPERSEDED,
                    context.keyService().get("b").orElseThrow().status());
            assertEquals(KeyStatus.ACTIVE,
                    context.keyService().get("b2").orElseThrow().status());

            ServiceException oldUnusable = assertThrows(ServiceException.class,
                    () -> context.sessionService()
                            .create("rot-3", Hex.encode("m".getBytes()), List.of("a", "b"), null));
            assertEquals(ErrorCode.KEY_SUPERSEDED, oldUnusable.errorCode());

            String newAggregate = context.aggregation()
                    .aggregatePublicHex(List.of("a", "b2"));
            assertNotEquals(oldAggregate, newAggregate);

            String msg = Hex.encode("post-rotation".getBytes(StandardCharsets.UTF_8));
            SessionRecord session = context.sessionService()
                    .create("rot-4", msg, List.of("a", "b2"), null);
            SessionRecord completed = MultisigFlowTest.runProtocol(
                    context, List.of(signers.get(0), b2), session);
            assertTrue(context.aggregation().verifyAggregate(
                    msg, completed.aggregatePubHex(), completed.aggregateSignatureHex()));
        } finally {
            context.close();
        }
    }
}
