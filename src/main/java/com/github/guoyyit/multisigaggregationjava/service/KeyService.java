package com.github.guoyyit.multisigaggregationjava.service;

import java.math.BigInteger;
import com.github.guoyyit.multisigaggregationjava.domain.RegisteredKey;
import com.github.guoyyit.multisigaggregationjava.crypto.EcPoint;
import com.github.guoyyit.multisigaggregationjava.crypto.Schnorr;
import com.github.guoyyit.multisigaggregationjava.domain.ErrorCode;
import com.github.guoyyit.multisigaggregationjava.domain.KeyStatus;
import com.github.guoyyit.multisigaggregationjava.domain.ServiceException;
import com.github.guoyyit.multisigaggregationjava.store.PersistentStateStore;

import java.time.Clock;
import java.util.List;

/**
 * Public key registration with mandatory proof of possession, key rotation and
 * auditable revocation.
 */
public class KeyService {

    private final PersistentStateStore store;
    private final Clock clock;

    public KeyService(PersistentStateStore store) {
        this(store, Clock.systemUTC());
    }

    public KeyService(PersistentStateStore store, Clock clock) {
        this.store = store;
        this.clock = clock;
        this.store.load();
    }

    /**
     * Register an active public key. The supplied Schnorr proof of possession
     * (over a server-defined message that binds the key id and public key) must
     * verify; otherwise registration is rejected.
     */
    public RegisteredKey register(String keyId, String publicKeyHex, String popSigHex, String popMessageHex) {
        requireText(keyId, "keyId");
        EcPoint publicKey = decodeKey(publicKeyHex);
        requireProofOfPossession(popMessageHex, popSigHex, publicKey);
        store.lock().writeLock().lock();
        try {
            RegisteredKey existing = store.getKey(keyId);
            if (existing != null) {
                throw new ServiceException(ErrorCode.KEY_ALREADY_REGISTERED,
                        "key id already registered: " + keyId);
            }
            RegisteredKey registered = new RegisteredKey(keyId, publicKey.encodeCompressedHex(),
                    KeyStatus.ACTIVE, popSigHex, popMessageHex, clock.millis(), null, null);
            store.putKey(registered);
            return registered;
        } finally {
            store.lock().writeLock().unlock();
        }
    }

    /**
     * Rotate a key: register a new key id bound to the previous one and revoke
     * the old one atomically. Historical aggregate signatures remain verifiable
     * because revoked public keys are retained for verification.
     */
    public RegisteredKey rotate(String oldKeyId, String newKeyId, String newPublicKeyHex,
                                String popSigHex, String popMessageHex) {
        requireText(oldKeyId, "oldKeyId");
        requireText(newKeyId, "newKeyId");
        EcPoint newPublicKey = decodeKey(newPublicKeyHex);
        requireProofOfPossession(popMessageHex, popSigHex, newPublicKey);
        store.lock().writeLock().lock();
        try {
            RegisteredKey old = store.getKey(oldKeyId);
            if (old == null) {
                throw new ServiceException(ErrorCode.KEY_NOT_FOUND, "unknown key id: " + oldKeyId);
            }
            if (store.getKey(newKeyId) != null) {
                throw new ServiceException(ErrorCode.KEY_ALREADY_REGISTERED,
                        "new key id already registered: " + newKeyId);
            }
            RegisteredKey rotated = new RegisteredKey(newKeyId, newPublicKey.encodeCompressedHex(),
                    KeyStatus.ACTIVE, popSigHex, popMessageHex, clock.millis(), null, null);
            RegisteredKey revokedOld = old.status() == KeyStatus.REVOKED ? old : new RegisteredKey(
                    old.keyId(), old.publicKeyHex(), KeyStatus.REVOKED, old.popSigHex(), old.popMessageHex(),
                    old.registeredAt(), clock.millis(), "rotated to " + newKeyId);
            store.putKey(rotated);
            store.putKey(revokedOld);
            return rotated;
        } finally {
            store.lock().writeLock().unlock();
        }
    }

    /** Revoke a key with an auditable reason. Revocation is idempotent. */
    public RegisteredKey revoke(String keyId, String reason) {
        store.lock().writeLock().lock();
        try {
            RegisteredKey existing = store.getKey(keyId);
            if (existing == null) {
                throw new ServiceException(ErrorCode.KEY_NOT_FOUND, "unknown key id: " + keyId);
            }
            if (existing.status() == KeyStatus.REVOKED) {
                return existing;
            }
            RegisteredKey revoked = new RegisteredKey(existing.keyId(), existing.publicKeyHex(),
                    KeyStatus.REVOKED, existing.popSigHex(), existing.popMessageHex(), existing.registeredAt(),
                    clock.millis(), reason == null || reason.isBlank() ? "revoked" : reason);
            store.putKey(revoked);
            return revoked;
        } finally {
            store.lock().writeLock().unlock();
        }
    }

    public RegisteredKey get(String keyId) {
        RegisteredKey key = store.getKey(keyId);
        if (key == null) {
            throw new ServiceException(ErrorCode.KEY_NOT_FOUND, "unknown key id: " + keyId);
        }
        return key;
    }

    public List<RegisteredKey> list() {
        return store.allKeys();
    }

    /** Fetch a key and require it to be present and active. */
    public RegisteredKey requireActive(String keyId) {
        RegisteredKey key = get(keyId);
        if (key.status() != KeyStatus.ACTIVE) {
            throw new ServiceException(ErrorCode.KEY_REVOKED, "key is revoked: " + keyId);
        }
        return key;
    }

    private static EcPoint decodeKey(String publicKeyHex) {
        try {
            return EcPoint.decodeCompressedHex(publicKeyHex);
        } catch (RuntimeException ex) {
            throw new ServiceException(ErrorCode.INVALID_PUBLIC_KEY,
                    "invalid public key encoding: " + ex.getMessage());
        }
    }

    private static void requireProofOfPossession(String popMessageHex, String popSigHex, EcPoint publicKey) {
        if (popMessageHex == null || popMessageHex.isBlank() || popSigHex == null || popSigHex.isBlank()) {
            throw new ServiceException(ErrorCode.INVALID_PROOF_OF_POSSESSION,
                    "proof of possession message and signature are required");
        }
        byte[] message;
        byte[] sig;
        try {
            message = hex(popMessageHex);
            sig = hex(popSigHex);
        } catch (IllegalArgumentException ex) {
            throw new ServiceException(ErrorCode.INVALID_PROOF_OF_POSSESSION,
                    "proof of possession values must be hex encoded");
        }
        if (sig.length != 65) {
            throw new ServiceException(ErrorCode.INVALID_PROOF_OF_POSSESSION,
                    "proof of possession signature must be R(33) || s(32) = 65 bytes");
        }
        try {
            EcPoint r = EcPoint.decodeCompressedHex(toHex(sig, 0, 33));
            BigInteger s = new BigInteger(1, java.util.Arrays.copyOfRange(sig, 33, 65));
            if (!Schnorr.verifyStandard(message, publicKey, r, s)) {
                throw new ServiceException(ErrorCode.INVALID_PROOF_OF_POSSESSION,
                        "proof of possession does not verify against the supplied public key");
            }
        } catch (ServiceException ex) {
            throw ex;
        } catch (RuntimeException ex) {
            throw new ServiceException(ErrorCode.INVALID_PROOF_OF_POSSESSION,
                    "malformed proof of possession signature: " + ex.getMessage());
        }
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new ServiceException(ErrorCode.INVALID_PUBLIC_KEY, name + " must not be blank");
        }
    }

    private static byte[] hex(String hex) {
        String s = hex.trim();
        if (s.length() % 2 != 0) {
            throw new IllegalArgumentException("odd-length hex");
        }
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int high = Character.digit(s.charAt(i * 2), 16);
            int low = Character.digit(s.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("invalid hex digit");
            }
            out[i] = (byte) ((high << 4) + low);
        }
        return out;
    }

    private static String toHex(byte[] bytes, int offset, int length) {
        StringBuilder sb = new StringBuilder(length * 2);
        for (int i = offset; i < offset + length; i++) {
            sb.append(Character.forDigit((bytes[i] >> 4) & 0xF, 16));
            sb.append(Character.forDigit(bytes[i] & 0xF, 16));
        }
        return sb.toString();
    }
}
