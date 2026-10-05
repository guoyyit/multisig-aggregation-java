package com.github.guoyyit.multisigaggregationjava.tests;

import com.github.guoyyit.multisigaggregationjava.core.Hex;
import com.github.guoyyit.multisigaggregationjava.signer.LocalSigner;
import com.github.guoyyit.multisigaggregationjava.web.AggregateController;
import com.github.guoyyit.multisigaggregationjava.web.AuditController;
import com.github.guoyyit.multisigaggregationjava.web.GlobalExceptionHandler;
import com.github.guoyyit.multisigaggregationjava.web.KeyController;
import com.github.guoyyit.multisigaggregationjava.web.SessionController;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class NewFeaturesWebApiTest extends ServiceTestBase {

    private MockMvc mvc;
    private Context context;

    @BeforeEach
    void setUp(@TempDir Path tempDir) {
        context = startContext(tempDir);
        mvc = MockMvcBuilders.standaloneSetup(
                        new KeyController(context.keyService()),
                        new SessionController(context.sessionService(), context.aggregation()),
                        new AggregateController(context.aggregation(), context.sessionService()),
                        new AuditController(context.auditLog()))
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @AfterEach
    void tearDown() {
        context.close();
    }

    @Test
    void proofEndpointReturnsPersistedProofAndReverifies() throws Exception {
        LocalSigner signer = LocalSigner.generate("web-pop", context.fileStore());
        String pop = signer.proofOfPossessionHex();
        String registerBody = "{\"keyId\":\"web-pop\",\"owner\":\"o\",\"pubHex\":\""
                + signer.publicKeyHex() + "\",\"popHex\":\"" + pop + "\"}";
        mvc.perform(post("/api/keys/register")
                        .contentType(MediaType.APPLICATION_JSON).content(registerBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.proofStatus").value("PRESENT"));

        mvc.perform(get("/api/keys/web-pop/proof"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.proofStatus").value("PRESENT"))
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.popHex").value(pop));
    }

    @Test
    void preemptiveRevokeThenRegisterIsRejectedWithDistinctReason() throws Exception {
        mvc.perform(post("/api/keys/web-tomb/revoke")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"reason\":\"r\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("REVOKED"));

        LocalSigner signer = LocalSigner.generate("web-tomb", context.fileStore());
        String registerBody = "{\"keyId\":\"web-tomb\",\"owner\":\"o\",\"pubHex\":\""
                + signer.publicKeyHex() + "\",\"popHex\":\""
                + signer.proofOfPossessionHex() + "\"}";
        mvc.perform(post("/api/keys/register")
                        .contentType(MediaType.APPLICATION_JSON).content(registerBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("KEY_REVOKED"));
    }

    @Test
    void offlineEndpointMarksSessionOfflineAndAuditReportsTruncatedCounter()
            throws Exception {
        MultisigFlowTest.registerSigners(context, List.of("oa", "ob"));
        String messageHex = Hex.encode("web-off".getBytes(StandardCharsets.UTF_8));
        mvc.perform(post("/api/sessions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sessionId\":\"off-web\",\"messageHex\":\"" + messageHex
                                + "\",\"participantKeyIds\":[\"oa\",\"ob\"]}"))
                .andExpect(status().isOk());

        mvc.perform(post("/api/sessions/off-web/offline")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyId\":\"ob\",\"reason\":\"unreachable\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.state").value("FAILED_RETRYABLE"))
                .andExpect(jsonPath("$.failureReason").value("OFFLINE"));

        mvc.perform(get("/api/audit"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.truncatedTrailingLines").value(0));
    }
}
