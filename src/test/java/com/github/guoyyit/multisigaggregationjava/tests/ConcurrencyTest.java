package com.github.guoyyit.multisigaggregationjava.tests;

import com.github.guoyyit.multisigaggregationjava.core.Hex;
import com.github.guoyyit.multisigaggregationjava.model.SessionRecord;
import com.github.guoyyit.multisigaggregationjava.model.SessionState;
import com.github.guoyyit.multisigaggregationjava.signer.LocalSigner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConcurrencyTest extends ServiceTestBase {

    @Test
    void duplicateRegistrationAndPartialSubmissionAreIdempotent(@TempDir Path tempDir) throws Exception {
        Context context = startContext(tempDir);
        try {
            LocalSigner signer = LocalSigner.generate("idem", context.fileStore());
            ExecutorService pool = Executors.newFixedThreadPool(8);
            List<Callable<Object>> tasks = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                tasks.add(() -> context.keyService().register(
                        "idem", "idem-owner",
                        signer.publicKeyHex(), signer.proofOfPossessionHex()));
            }
            for (Future<Object> future : pool.invokeAll(tasks)) {
                future.get();
            }
            pool.shutdown();
            assertEquals(1, context.keyService().list(null).size());

            LocalSigner other = LocalSigner.generate("idem-other", context.fileStore());
            context.keyService().register("idem-other", "o",
                    other.publicKeyHex(), other.proofOfPossessionHex());
            String msg = Hex.encode("idem-msg".getBytes(StandardCharsets.UTF_8));
            SessionRecord session = context.sessionService()
                    .create("idem-sess", msg, List.of("idem", "idem-other"), null);
            SessionRecord completed = MultisigFlowTest.runProtocol(
                    context, List.of(signer, other), session);

            SessionRecord again = context.sessionService().submitPartial(
                    "idem-sess", "idem", completed.partialSignatures().get("idem"));
            assertEquals(SessionState.COMPLETED, again.state());
            assertEquals(2, again.partialSignatures().size());
        } finally {
            context.close();
        }
    }

    @Test
    void multipleSessionsProgressIndependently(@TempDir Path tempDir) throws Exception {
        Context context = startContext(tempDir);
        try {
            List<LocalSigner> signers = MultisigFlowTest.registerSigners(
                    context, List.of("a", "b", "c"));
            List<String> ids = List.of("p1", "p2", "p3", "p4");
            ExecutorService pool = Executors.newFixedThreadPool(4);
            List<Future<SessionState>> futures = new ArrayList<>();
            for (String id : ids) {
                futures.add(pool.submit(() -> {
                    String msg = Hex.encode((">msg-" + id).getBytes(StandardCharsets.UTF_8));
                    SessionRecord session = context.sessionService()
                            .create(id, msg, List.of("a", "b", "c"), null);
                    return MultisigFlowTest.runProtocol(context, signers, session).state();
                }));
            }
            for (Future<SessionState> future : futures) {
                assertEquals(SessionState.COMPLETED, future.get());
            }
            pool.shutdown();

            for (String id : ids) {
                SessionRecord session = context.sessionService().get(id);
                String msg = Hex.encode((">msg-" + id).getBytes(StandardCharsets.UTF_8));
                assertTrue(context.aggregation().verifyAggregate(
                        msg, session.aggregatePubHex(), session.aggregateSignatureHex()));
            }
        } finally {
            context.close();
        }
    }
}
