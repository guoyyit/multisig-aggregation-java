package com.github.guoyyit.multisigaggregationjava.tests.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.multisigaggregationjava.crypto.CurveP256;
import com.github.guoyyit.multisigaggregationjava.crypto.LocalSigner;
import com.github.guoyyit.multisigaggregationjava.crypto.Schnorr;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** REST-level smoke and error-code tests. */
@SpringBootTest
@AutoConfigureMockMvc
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestPropertySource(properties = "multisig.sweep-interval-millis=3600000")
class WebApiTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;

    private final LocalSigner alice = LocalSigner.generate();
    private final LocalSigner bob = LocalSigner.generate();

    private static final java.nio.file.Path STATE_FILE;

    static {
        try {
            STATE_FILE = Files.createTempDirectory("multisig-webapi-").resolve("state.json");
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @DynamicPropertySource
    static void stateFile(DynamicPropertyRegistry registry) {
        registry.add("multisig.state-file", () -> STATE_FILE.toString());
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    private String pop(String keyId, LocalSigner signer) throws Exception {
        String pk = signer.publicKey().encodeCompressedHex();
        byte[] message = ("pop:" + keyId + ":" + pk).getBytes(StandardCharsets.UTF_8);
        Schnorr.StandardSignature signature = signer.signStandard(message);
        return objectMapper.writeValueAsString(new java.util.LinkedHashMap<>() {{
            put("keyId", keyId);
            put("publicKeyHex", pk);
            put("popSigHex", signature.r().encodeCompressedHex() + scalar32(signature.s()));
            put("popMessageHex", hex(message));
        }});
    }

    private static String scalar32(java.math.BigInteger scalar) {
        byte[] raw = scalar.toByteArray();
        byte[] out = new byte[32];
        System.arraycopy(raw, Math.max(0, raw.length - 32), out, 32 - Math.min(32, raw.length),
                Math.min(32, raw.length));
        return hex(out);
    }

    @BeforeAll
    void registerKeys() throws Exception {
        mockMvc.perform(post("/api/keys").contentType(MediaType.APPLICATION_JSON).content(pop("http-alice", alice)))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/keys").contentType(MediaType.APPLICATION_JSON).content(pop("http-bob", bob)))
                .andExpect(status().isOk());
    }

    @Test
    void fullFlowOverHttp() throws Exception {
        String createBody = objectMapper.writeValueAsString(new java.util.LinkedHashMap<>() {{
            put("sessionId", "http-session");
            put("messageHex", hex("http message".getBytes(StandardCharsets.UTF_8)));
            put("participantKeyIds", List.of("http-alice", "http-bob"));
        }});
        mockMvc.perform(post("/api/sessions").contentType(MediaType.APPLICATION_JSON).content(createBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("OPEN"));

        commit("http-session", "http-alice", alice, 1);
        commit("http-session", "http-bob", bob, 1);

        JsonNode view = readView("http-session");
        partial("http-session", "http-alice", alice, view, false);
        partial("http-session", "http-bob", bob, view, true);

        mockMvc.perform(get("/api/sessions/http-session/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true));
        JsonNode completed = objectMapper.readTree(mockMvc.perform(get("/api/sessions/http-session"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        JsonNode agg = completed.get("aggregateSignature");
        mockMvc.perform(post("/api/sessions/verify").contentType(MediaType.APPLICATION_JSON)
                        .content(standaloneVerifyBody(agg)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true));
    }

    @Test
    void missingKeyReturnsStableErrorCode() throws Exception {
        String body = objectMapper.writeValueAsString(new java.util.LinkedHashMap<>() {{
            put("sessionId", "missing-key-session");
            put("messageHex", "6d");
            put("participantKeyIds", List.of("ghost"));
        }});
        mockMvc.perform(post("/api/sessions").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("KEY_NOT_FOUND"));
    }

    @Test
    void invalidProofOfPossessionReturnsDistinctCode() throws Exception {
        String body = objectMapper.writeValueAsString(new java.util.LinkedHashMap<>() {{
            put("keyId", "bad-pop");
            put("publicKeyHex", alice.publicKey().encodeCompressedHex());
            put("popSigHex", alice.publicKey().encodeCompressedHex() + scalar32(CurveP256.randomScalar()));
            put("popMessageHex", "6d");
        }});
        mockMvc.perform(post("/api/keys").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_PROOF_OF_POSSESSION"));
    }

    private void commit(String sessionId, String keyId, LocalSigner signer, int round) throws Exception {
        var commitment = signer.newCommitment(sessionId, round, true);
        String body = objectMapper.writeValueAsString(new java.util.LinkedHashMap<>() {{
            put("keyId", keyId);
            put("r1Hex", commitment.r1Hex());
            put("r2Hex", commitment.r2Hex());
        }});
        mockMvc.perform(post("/api/sessions/" + sessionId + "/commitments")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk());
    }

    private JsonNode readView(String sessionId) throws Exception {
        String response = mockMvc.perform(get("/api/sessions/" + sessionId + "/view"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(response);
    }

    private void partial(String sessionId, String keyId, LocalSigner signer, JsonNode view, boolean expectDone)
            throws Exception {
        var signingView = new com.github.guoyyit.multisigaggregationjava.domain.SigningView(
                view.get("sessionId").asText(), view.get("round").asInt(),
                view.get("messageHex").asText(),
                objectMapper.convertValue(view.get("participantKeyIds"),
                        objectMapper.getTypeFactory().constructCollectionType(List.class, String.class)),
                objectMapper.convertValue(view.get("publicKeysHex"),
                        objectMapper.getTypeFactory().constructCollectionType(List.class, String.class)),
                view.get("aggregateKeyHex").asText(), view.get("rHex").asText(),
                view.get("bHex").asText(), view.get("eHex").asText());
        java.math.BigInteger partialScalar = signer.signPartial(signingView);
        String body = objectMapper.writeValueAsString(new java.util.LinkedHashMap<>() {{
            put("keyId", keyId);
            put("scalarHex", scalar32(partialScalar));
        }});
        mockMvc.perform(post("/api/sessions/" + sessionId + "/partials")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk());
    }

    private String standaloneVerifyBody(JsonNode agg) throws Exception {
        return objectMapper.writeValueAsString(new java.util.LinkedHashMap<>() {{
            put("messageHex", agg.get("messageHex").asText());
            put("aggregateKeyHex", agg.get("aggregateKeyHex").asText());
            put("rHex", agg.get("rHex").asText());
            put("sHex", agg.get("sHex").asText());
        }});
    }
}
