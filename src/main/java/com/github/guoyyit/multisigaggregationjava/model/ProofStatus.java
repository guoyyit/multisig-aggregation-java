package com.github.guoyyit.multisigaggregationjava.model;

/**
 * 所有权证明（PoP）随注册记录持久化后的可查证状态。
 * 升级前写入、不含证明字段的旧记录一律归为 LEGACY_MISSING，
 * 服务正常加载、状态可解释，且仍可参与新会话。
 */
public enum ProofStatus {
    /** 已随注册/轮换提交并通过校验的所有权证明，可随时取回重新验证。 */
    PRESENT,
    /** 升级前的旧注册记录，不含证明信息；记录本身仍有效。 */
    LEGACY_MISSING,
    /** 先撤销后注册场景下的撤销墓碑，从未存在过公钥材料，证明不适用。 */
    NOT_APPLICABLE
}
