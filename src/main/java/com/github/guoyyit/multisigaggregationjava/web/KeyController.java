package com.github.guoyyit.multisigaggregationjava.web;

import com.github.guoyyit.multisigaggregationjava.core.ErrorCode;
import com.github.guoyyit.multisigaggregationjava.core.ServiceException;
import com.github.guoyyit.multisigaggregationjava.model.KeyStatus;
import com.github.guoyyit.multisigaggregationjava.model.PublicKeyRecord;
import com.github.guoyyit.multisigaggregationjava.service.KeyService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/keys")
public class KeyController {

    public record RegisterRequest(String keyId, String owner, String pubHex, String popHex) {
    }

    public record RotateRequest(String oldKeyId, String newKeyId, String newPubHex, String popHex) {
    }

    private final KeyService keyService;

    public KeyController(KeyService keyService) {
        this.keyService = keyService;
    }

    @PostMapping("/register")
    public Map<String, Object> register(@RequestBody RegisterRequest request) {
        require(request != null, "请求体为空");
        require(request.keyId() != null, "keyId 不能为空");
        require(request.pubHex() != null, "pubHex 不能为空");
        PublicKeyRecord record = keyService.register(
                request.keyId(), request.owner(), request.pubHex(), request.popHex());
        return view(record);
    }

    @PostMapping("/rotate")
    public Map<String, Object> rotate(@RequestBody RotateRequest request) {
        require(request != null, "请求体为空");
        PublicKeyRecord fresh = keyService.rotate(
                request.oldKeyId(), request.newKeyId(), request.newPubHex(), request.popHex());
        return view(fresh);
    }

    @PostMapping("/{keyId}/revoke")
    public Map<String, Object> revoke(@PathVariable String keyId,
                                      @RequestBody(required = false) Map<String, String> body) {
        String reason = body == null ? null : body.getOrDefault("reason", null);
        return view(keyService.revoke(keyId, reason));
    }

    @GetMapping("/{keyId}")
    public Map<String, Object> get(@PathVariable String keyId) {
        PublicKeyRecord record = keyService.get(keyId)
                .orElseThrow(() -> new ServiceException(ErrorCode.KEY_NOT_FOUND));
        return view(record);
    }

    /**
     * 查证（并重新验证）注册/轮换时持久化的所有权证明。
     * 旧记录返回 LEGACY_MISSING、valid=false；正常记录返回 PRESENT 及重验结果。
     */
    @GetMapping("/{keyId}/proof")
    public Map<String, Object> proof(@PathVariable String keyId) {
        PublicKeyRecord record = keyService.get(keyId)
                .orElseThrow(() -> new ServiceException(ErrorCode.KEY_NOT_FOUND));
        KeyService.ProofVerification verification = keyService.verifyStoredProof(keyId);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("keyId", keyId);
        body.put("pubHex", record.pubHex());
        body.put("proofStatus", record.proofStatus().name());
        body.put("popHex", record.popHex());
        body.put("valid", verification.valid());
        return body;
    }

    @GetMapping
    public Map<String, Object> list(@RequestParam(required = false) String status) {
        KeyStatus keyStatus = null;
        if (status != null && !status.isBlank()) {
            try {
                keyStatus = KeyStatus.valueOf(status.trim().toUpperCase());
            } catch (IllegalArgumentException ex) {
                throw new ServiceException(ErrorCode.VALIDATION_ERROR, "未知状态: " + status);
            }
        }
        List<Map<String, Object>> keys = keyService.list(keyStatus).stream()
                .map(KeyController::view).toList();
        return Map.of("keys", keys);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new ServiceException(ErrorCode.VALIDATION_ERROR, message);
        }
    }

    static Map<String, Object> view(PublicKeyRecord record) {
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("keyId", record.keyId());
        view.put("owner", record.owner());
        view.put("pubHex", record.pubHex());
        view.put("proofStatus", record.proofStatus().name());
        view.put("popHex", record.popHex());
        view.put("status", record.status().name());
        view.put("version", record.version());
        view.put("registeredAt", record.registeredAt());
        view.put("revokedAt", record.revokedAt());
        view.put("replacedById", record.replacedById());
        return view;
    }
}
