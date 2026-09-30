package com.github.guoyyit.multisigaggregationjava.tests;

import com.github.guoyyit.multisigaggregationjava.core.ErrorCode;
import com.github.guoyyit.multisigaggregationjava.core.Hex;
import com.github.guoyyit.multisigaggregationjava.core.Schnorr;
import com.github.guoyyit.multisigaggregationjava.core.ServiceException;
import com.github.guoyyit.multisigaggregationjava.model.SessionRecord;
import com.github.guoyyit.multisigaggregationjava.model.SessionState;
import com.github.guoyyit.multisigaggregationjava.signer.LocalSigner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class NonceReuseTest extends ServiceTestBase {

    private final SecureRandom random = new SecureRandom();

    @Test
    void conflictingCommitmentRejectedWithDistinctErrorCode(@TempDir Path tempDir) {
        Context context = startContext(tempDir);
        try {
            List<LocalSigner> signers = MultisigFlowTest.registerSigners(
                    context, List.of("a", "b"));
            String msg = Hex.encode("m".getBytes(StandardCharsets.UTF_8));
            SessionRecord session = context.sessionService()
                    .create("n1", msg, List.of("a", "b"), null);

            context.sessionService().submitCommitment("n1", "a",
                    signers.get(0).commitment("n1", session.saltHex()));

            String otherCommitment = Hex.encode(Schnorr.taggedHash(
                    "x", new byte[]{1}));
            ServiceException ex = assertThrows(ServiceException.class,
                    () -> context.sessionService().submitCommitment("n1", "a", otherCommitment));
            assertEquals(ErrorCode.COMMITMENT_DUPLICATE, ex.errorCode());
            assertEquals(SessionState.FAILED_RETRYABLE,
                    context.sessionService().get("n1").state());
        } finally {
            context.close();
        }
    }

    @Test
    void sameNonceAcrossSessionsRejected(@TempDir Path tempDir) {
        Context context = startContext(tempDir);
        try {
            MultisigFlowTest.registerSigners(context, List.of("a", "b"));
            String msg = Hex.encode("m".getBytes(StandardCharsets.UTF_8));
            SessionRecord s1 = context.sessionService()
                    .create("r1", msg, List.of("a", "b"), null);
            SessionRecord s2 = context.sessionService()
                    .create("r2", Hex.encode("n".getBytes(StandardCharsets.UTF_8)),
                            List.of("a", "b"), null);

            BigInteger k = Schnorr.randomScalar(random);
            String reusedNonce = Hex.encode(
                    Schnorr.compress(Schnorr.scalarBaseMult(k)));

            context.sessionService().submitCommitment("r1", "a",
                    Hex.encode(com.github.guoyyit.multisigaggregationjava.core.Musig
                            .commitment("r1", Hex.decode(reusedNonce), Hex.decode(s1.saltHex()))));
            context.sessionService().submitNonce("r1", "a", reusedNonce);

            context.sessionService().submitCommitment("r2", "a",
                    Hex.encode(com.github.guoyyit.multisigaggregationjava.core.Musig
                            .commitment("r2", Hex.decode(reusedNonce), Hex.decode(s2.saltHex()))));
            ServiceException ex = assertThrows(ServiceException.class,
                    () -> context.sessionService().submitNonce("r2", "a", reusedNonce));
            assertEquals(ErrorCode.NONCE_REUSE, ex.errorCode());
            assertEquals(SessionState.FAILED_RETRYABLE,
                    context.sessionService().get("r2").state());
        } finally {
            context.close();
        }
    }

    @Test
    void duplicateNoncePointWithinOneSessionRejected(@TempDir Path tempDir) {
        Context context = startContext(tempDir);
        try {
            MultisigFlowTest.registerSigners(context, List.of("a", "b"));
            String msg = Hex.encode("m".getBytes(StandardCharsets.UTF_8));
            SessionRecord s1 = context.sessionService()
                    .create("d1", msg, List.of("a", "b"), null);

            BigInteger k = Schnorr.randomScalar(random);
            String reusedNonce = Hex.encode(
                    Schnorr.compress(Schnorr.scalarBaseMult(k)));
            String commitment = Hex.encode(com.github.guoyyit.multisigaggregationjava.core.Musig
                    .commitment("d1", Hex.decode(reusedNonce), Hex.decode(s1.saltHex())));
            context.sessionService().submitCommitment("d1", "a", commitment);

            ServiceException ex = assertThrows(ServiceException.class,
                    () -> context.sessionService().submitCommitment("d1", "b", commitment));
            assertEquals(ErrorCode.COMMITMENT_DUPLICATE, ex.errorCode());
            assertEquals(SessionState.FAILED_RETRYABLE,
                    context.sessionService().get("d1").state());
        } finally {
            context.close();
        }
    }
}
