package com.github.guoyyit.multisigaggregationjava.model;

public record PublicKeyRecord(
        String keyId,
        String owner,
        String pubHex,
        KeyStatus status,
        int version,
        long registeredAt,
        long revokedAt,
        String replacedById,
        String popHex
) {
    public static PublicKeyRecord empty() {
        return new PublicKeyRecord(null, null, null, null, 0, 0L, 0L, null, null);
    }

    /**
     * 所有权证明的持久化状态：PRESENT 表示随记录保存了 PoP；
     * LEGACY_MISSING 表示升级前写入的旧记录，本身不含证明，属可解释的正常状态。
     */
    public String popStatus() {
        return popHex == null || popHex.isBlank() ? "LEGACY_MISSING" : "PRESENT";
    }
}
