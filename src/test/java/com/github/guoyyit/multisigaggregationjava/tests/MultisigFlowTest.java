package com.github.guoyyit.multisigaggregationjava.tests;

import com.github.guoyyit.multisigaggregationjava.core.Hex;
import com.github.guoyyit.multisigaggregationjava.model.SessionRecord;
import com.github.guoyyit.multisigaggregationjava.model.SessionState;
import com.github.guoyyit.multisigaggregationjava.service.AggregationService;
import com.github.guoyyit.multisigaggregationjava.service.SessionService;
import com.github.guoyyit.multisigaggregationjava.signer.LocalSigner;
import com.github.guoyyit.multisigaggregationjava.store.FileStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MultisigFlowTest extends ServiceTestBase {

    @Test
    void threePartyAggregationVerifiesAndMatchesIndividualChecks(@TempDir Path tempDir) {
        ServiceTestBase.Context context = startContext(tempDir);
        try {
            SessionService sessionService = context.sessionService();
            AggregationService aggregation = context.aggregation();

            List<LocalSigner> signers = registerSigners(context, List.of("alice", "bob", "carol"));
            List<String> keyIds = signers.stream().map(LocalSigner::keyId).toList();
            String messageHex = Hex.encode("pay 10".getBytes(StandardCharsets.UTF_8));

            SessionRecord session = sessionService.create("sess-3", messageHex, keyIds, null);
            SessionRecord completed = runProtocol(context, signers, session);

            assertEquals(SessionState.COMPLETED, completed.state());
            assertTrue(aggregation.verifyPartialsIndividually(session.sessionId()));
            assertTrue(aggregation.verifyAggregate(
                    messageHex, completed.aggregatePubHex(), completed.aggregateSignatureHex()));

            String otherMessage = Hex.encode("pay 99".getBytes(StandardCharsets.UTF_8));
            assertTrue(!aggregation.verifyAggregate(
                    otherMessage, completed.aggregatePubHex(), completed.aggregateSignatureHex()));
        } finally {
            context.close();
        }
    }

    @Test
    void singleSignerFlowIsPlainSchnorrAndInteroperable(@TempDir Path tempDir) {
        ServiceTestBase.Context context = startContext(tempDir);
        try {
            List<LocalSigner> signers = registerSigners(context, List.of("solo"));
            String messageHex = Hex.encode("single".getBytes(StandardCharsets.UTF_8));
            SessionRecord session = context.sessionService()
                    .create("sess-solo", messageHex, List.of("solo"), null);
            SessionRecord completed = runProtocol(context, signers, session);

            assertEquals(signers.get(0).publicKeyHex(), completed.aggregatePubHex());
            assertTrue(context.aggregation().verifyAggregate(
                    messageHex, completed.aggregatePubHex(), completed.aggregateSignatureHex()));
        } finally {
            context.close();
        }
    }

    static List<LocalSigner> registerSigners(ServiceTestBase.Context context, List<String> keyIds) {
        List<LocalSigner> signers = new ArrayList<>();
        for (String keyId : keyIds) {
            LocalSigner signer = LocalSigner.generate(keyId, context.fileStore());
            context.keyService().register(
                    keyId, keyId + "-owner", signer.publicKeyHex(), signer.proofOfPossessionHex());
            signers.add(signer);
        }
        return signers;
    }

    static SessionRecord runProtocol(ServiceTestBase.Context context,
                                     List<LocalSigner> signers,
                                     SessionRecord session) {
        String sessionId = session.sessionId();
        String saltHex = session.saltHex();
        for (LocalSigner signer : signers) {
            String commitment = signer.commitment(sessionId, saltHex);
            context.sessionService().submitCommitment(sessionId, signer.keyId(), commitment);
        }
        List<String> nonceHexes = new ArrayList<>();
        for (LocalSigner signer : signers) {
            String nonceHex = signer.nonce(sessionId);
            context.sessionService().submitNonce(sessionId, signer.keyId(), nonceHex);
            nonceHexes.add(nonceHex);
        }
        List<String> pubHexes = signers.stream().map(LocalSigner::publicKeyHex).toList();
        SessionRecord latest = session;
        for (LocalSigner signer : signers) {
            String partial = signer.partialSignature(
                    sessionId, session.messageHex(), pubHexes, nonceHexes);
            latest = context.sessionService().submitPartial(sessionId, signer.keyId(), partial);
        }
        return latest;
    }
}
