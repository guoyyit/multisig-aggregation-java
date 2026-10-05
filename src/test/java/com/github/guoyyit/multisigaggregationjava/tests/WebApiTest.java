package com.github.guoyyit.multisigaggregationjava.tests;

import com.github.guoyyit.multisigaggregationjava.core.Hex;
import com.github.guoyyit.multisigaggregationjava.signer.LocalSigner;
import com.github.guoyyit.multisigaggregationjava.store.FileStore;
import com.github.guoyyit.multisigaggregationjava.web.AggregateController;
import com.github.guoyyit.multisigaggregationjava.web.AuditController;
import com.github.guoyyit.multisigaggregationjava.web.GlobalExceptionHandler;
import com.github.guoyyit.multisigaggregationjava.web.KeyController;
import com.github.guoyyit.multisigaggregationjava.web.SessionController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class WebApiTest extends ServiceTestBase {

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
    void missingProofOfPossessionReturnsDistinctErrorCode() throws Exception {
        LocalSigner signer = LocalSigner.generate("web-a", context.fileStore());
        String body = "{\"keyId\":\"web-a\",\"owner\":\"o\",\"pubHex\":\""
                + signer.publicKeyHex() + "\"}";
        mvc.perform(post("/api/keys/register")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("POP_MISSING"));
    }

    @Test
    void unknownSessionReturns404() throws Exception {
        mvc.perform(get("/api/sessions/does-not-exist"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("SESSION_NOT_FOUND"));
    }

    @Test
    void proofOfPossessionIsQueryableOverHttp() throws Exception {
        LocalSigner signer = LocalSigner.generate("web-pop", context.fileStore());
        String pop = signer.proofOfPossessionHex();
        String registerBody = "{\"keyId\":\"web-pop\",\"owner\":\"o\",\"pubHex\":\""
                + signer.publicKeyHex() + "\",\"popHex\":\"" + pop + "\"}";
        mvc.perform(post("/api/keys/register")
                        .contentType(MediaType.APPLICATION_JSON).content(registerBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.popStatus").value("PRESENT"));

        mvc.perform(get("/api/keys/web-pop/pop"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.popStatus").value("PRESENT"))
                .andExpect(jsonPath("$.popHex").value(pop))
                .andExpect(jsonPath("$.valid").value(true));
    }

    @Test
    void offlineMarkingAndAuditCorruptionCounterOverHttp() throws Exception {
        LocalSigner signer = LocalSigner.generate("web-off", context.fileStore());
        String registerBody = "{\"keyId\":\"web-off\",\"owner\":\"o\",\"pubHex\":\""
                + signer.publicKeyHex() + "\",\"popHex\":\""
                + signer.proofOfPossessionHex() + "\"}";
        mvc.perform(post("/api/keys/register")
                        .contentType(MediaType.APPLICATION_JSON).content(registerBody))
                .andExpect(status().isOk());

        String messageHex = Hex.encode("web offline".getBytes(StandardCharsets.UTF_8));
        String createBody = "{\"sessionId\":\"web-off-1\",\"messageHex\":\"" + messageHex
                + "\",\"participantKeyIds\":[\"web-off\"]}";
        mvc.perform(post("/api/sessions")
                        .contentType(MediaType.APPLICATION_JSON).content(createBody))
                .andExpect(status().isOk());

        mvc.perform(post("/api/sessions/web-off-1/offline")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"keyId\":\"web-off\",\"reason\":\"unreachable\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.state").value("FAILED_RETRYABLE"))
                .andExpect(jsonPath("$.failureReason").value("OFFLINE"));

        mvc.perform(get("/api/audit"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.corruptedLines").value(0))
                .andExpect(jsonPath("$.total").isNumber());
    }

    @Test
    void fullHttpRoundTripForSingleSigner() throws Exception {
        FileStore store = context.fileStore();
        LocalSigner signer = LocalSigner.generate("web-solo", store);
        String registerBody = "{\"keyId\":\"web-solo\",\"owner\":\"solo\",\"pubHex\":\""
                + signer.publicKeyHex() + "\",\"popHex\":\""
                + signer.proofOfPossessionHex() + "\"}";
        mvc.perform(post("/api/keys/register")
                        .contentType(MediaType.APPLICATION_JSON).content(registerBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACTIVE"));

        String messageHex = Hex.encode("http message".getBytes(StandardCharsets.UTF_8));
        String createBody = "{\"sessionId\":\"web-session\",\"messageHex\":\"" + messageHex
                + "\",\"participantKeyIds\":[\"web-solo\"]}";
        String createResponse = mvc.perform(post("/api/sessions")
                        .contentType(MediaType.APPLICATION_JSON).content(createBody))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String salt = new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree(createResponse).get("saltHex").asText();

        String commitmentBody = "{\"keyId\":\"web-solo\",\"commitmentHex\":\""
                + signer.commitment("web-session", salt) + "\"}";
        mvc.perform(post("/api/sessions/web-session/commitments")
                        .contentType(MediaType.APPLICATION_JSON).content(commitmentBody))
                .andExpect(status().isOk());

        String nonce = signer.nonce("web-session");
        String nonceBody = "{\"keyId\":\"web-solo\",\"nonceHex\":\"" + nonce + "\"}";
        mvc.perform(post("/api/sessions/web-session/nonces")
                        .contentType(MediaType.APPLICATION_JSON).content(nonceBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.state").value("COLLECTING_SIGNATURES"));

        String partial = signer.partialSignature("web-session", messageHex,
                java.util.List.of(signer.publicKeyHex()), java.util.List.of(nonce));
        String partialBody = "{\"keyId\":\"web-solo\",\"partialHex\":\"" + partial + "\"}";
        mvc.perform(post("/api/sessions/web-session/partials")
                        .contentType(MediaType.APPLICATION_JSON).content(partialBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.state").value("COMPLETED"))
                .andExpect(jsonPath("$.aggregateSignatureHex").isNotEmpty());
    }
}
