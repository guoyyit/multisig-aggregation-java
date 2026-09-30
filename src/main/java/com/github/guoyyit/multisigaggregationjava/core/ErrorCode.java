package com.github.guoyyit.multisigaggregationjava.core;

public enum ErrorCode {
    VALIDATION_ERROR("VALIDATION_ERROR", "请求参数无效"),
    INVALID_PUBLIC_KEY("INVALID_PUBLIC_KEY", "公钥编码无效或不在曲线上"),
    POP_MISSING("POP_MISSING", "缺少公钥所有权证明"),
    POP_INVALID("POP_INVALID", "公钥所有权证明验证失败"),
    KEY_NOT_FOUND("KEY_NOT_FOUND", "公钥不存在"),
    DUPLICATE_KEY_ID("DUPLICATE_KEY_ID", "密钥 ID 已存在"),
    KEY_REVOKED("KEY_REVOKED", "公钥已被撤销"),
    KEY_SUPERSEDED("KEY_SUPERSEDED", "公钥已被轮换取代"),
    INVALID_MESSAGE("INVALID_MESSAGE", "消息编码无效"),
    SESSION_NOT_FOUND("SESSION_NOT_FOUND", "会话不存在"),
    SESSION_NOT_ACTIVE("SESSION_NOT_ACTIVE", "会话当前状态不接受该操作"),
    SESSION_ALREADY_FINALIZED("SESSION_ALREADY_FINALIZED", "会话承诺已最终化"),
    UNKNOWN_PARTICIPANT("UNKNOWN_PARTICIPANT", "提交方不属于本会话"),
    COMMITMENT_DUPLICATE("COMMITMENT_DUPLICATE", "会话内已存在相同承诺（随机数重用）"),
    NONCE_COMMITMENT_MISMATCH("NONCE_COMMITMENT_MISMATCH", "公开随机数与先前承诺不一致"),
    DUPLICATE_NONCE("DUPLICATE_NONCE", "会话内检测到重复的随机数点"),
    NONCE_REUSE("NONCE_REUSE", "检测到跨会话或跨消息随机数重用"),
    INVALID_PARTIAL_SIGNATURE("INVALID_PARTIAL_SIGNATURE", "部分签名验证失败"),
    SESSION_INCOMPLETE("SESSION_INCOMPLETE", "仍有参与方未提交，聚合不完整"),
    SESSION_NOT_READY("SESSION_NOT_READY", "尚未收集到全部部分签名"),
    SESSION_NOT_RETRYABLE("SESSION_NOT_RETRYABLE", "该会话不可重试"),
    SESSION_EXPIRED("SESSION_EXPIRED", "会话已超时"),
    CONCURRENT_UPDATE("CONCURRENT_UPDATE", "并发更新冲突，请重试"),
    INTERNAL_ERROR("INTERNAL_ERROR", "内部错误");

    private final String code;
    private final String defaultMessage;

    ErrorCode(String code, String defaultMessage) {
        this.code = code;
        this.defaultMessage = defaultMessage;
    }

    public String code() {
        return code;
    }

    public String defaultMessage() {
        return defaultMessage;
    }
}
