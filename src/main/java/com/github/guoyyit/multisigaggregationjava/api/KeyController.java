package com.github.guoyyit.multisigaggregationjava.api;

import com.github.guoyyit.multisigaggregationjava.domain.RegisteredKey;
import com.github.guoyyit.multisigaggregationjava.service.KeyService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/** Public key registration, rotation and revocation endpoints. */
@RestController
@RequestMapping("/api/keys")
public class KeyController {

    private final KeyService keyService;

    public KeyController(KeyService keyService) {
        this.keyService = keyService;
    }

    @PostMapping
    public RegisteredKey register(@RequestBody ApiDtos.RegisterKeyRequest request) {
        return keyService.register(request.keyId(), request.publicKeyHex(),
                request.popSigHex(), request.popMessageHex());
    }

    @PostMapping("/rotate")
    public RegisteredKey rotate(@RequestBody ApiDtos.RotateKeyRequest request) {
        return keyService.rotate(request.oldKeyId(), request.newKeyId(), request.newPublicKeyHex(),
                request.popSigHex(), request.popMessageHex());
    }

    @PostMapping("/{keyId}/revoke")
    public RegisteredKey revoke(@PathVariable String keyId, @RequestBody ApiDtos.RevokeKeyRequest request) {
        return keyService.revoke(keyId, request.reason());
    }

    @GetMapping("/{keyId}")
    public RegisteredKey get(@PathVariable String keyId) {
        return keyService.get(keyId);
    }

    @GetMapping
    public List<RegisteredKey> list() {
        return keyService.list();
    }
}
