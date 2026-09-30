# 安全设计与协议说明

本文档说明本服务的协议假设、安全边界、所抵御的攻击，以及各错误码的含义。

## 1. 协议概述

本服务在 NIST P-256（secp256r1）上实现 **MuSig2 风格的两轮 Schnorr 多签名聚合**，
哈希使用 SHA-256（带标签哈希，BIP-340 风格 `taggedHash`）。

- 每个签名方在本地持有私钥 `x_i`，服务端只看到公钥 `X_i = x_i·G`。
- 密钥聚合：参与方公钥按压缩编码的字典序排序，
  `a_i = H_tag("KeyAgg/v1", L || X_i)`，`L = H_tag("KeyAgg/list/v1", X_1||…||X_n)`，
  聚合公钥 `X = Σ a_i·X_i`。
- 签名采用两个随机数（MuSig2）：每方提交承诺 `R1_i, R2_i`；
  `b = H_tag("MuSig2/noncecoef/v1", X || R1 || R2 || m)`，
  `R = Σ R1_i + b·Σ R2_i`，挑战 `e = H_tag("SchnorrSign/v1", R || X || m)`。
- 部分签名 `s_i = k1_i + b·k2_i + e·a_i·x_i mod n`，
  聚合签名 `s = Σ s_i mod n`，最终验证 `s·G = R + e·X`。

### 单方退化

当会话只有一个参与方时，协议退化为标准 Schnorr：
`a = 1`、`b = 0`、只用一个随机数，`X = X_1`，
聚合签名 `(R, s)` 与标准 Schnorr 签名完全互通，可被
`POST /api/sessions/verify` 用该公钥独立验证。

## 2. 协议假设

1. 签名方使用密码学安全的随机源（`SecureRandom`）生成私钥与每轮随机数。
2. 私钥与秘密随机数永不离开签名方本地；服务端不接收、不存储任何秘密材料。
3. 每个 `(会话, 轮次)` 使用全新随机数；秘密随机数在生成一次部分签名后即丢弃。
4. 通信发生在本地可信环境；本服务不提供传输层加密、身份认证或授权。
5. 参与方就待签消息与参与方集合达成一致（会话创建时固定，不可中途变更）。
6. 持久化状态文件所在目录是可信本地存储，攻击者无法在运行时改写它。

## 3. 抵御的攻击

### 3.1 恶意 / 流氓公钥（Rogue-Key Attack）

服务采用两层防御：

1. **所有权证明（Proof of Possession, PoP）**：注册时必须提交对一条
   绑定 `keyId || 公钥` 的消息的标准 Schnorr 签名，证明注册者掌握对应私钥。
   PoP 验证失败则拒绝注册（`INVALID_PROOF_OF_POSSESSION`）。
   因此攻击者无法注册形如 `X_att = R − a_v·X_v` 这类其不知离散对数的构造公钥。
2. **每密钥聚合系数**：`X = Σ a_i·X_i` 中各公钥被绑定到由完整参与方列表
   导出的系数，消除朴素求和聚合的 rogue-key 代数自由度。

测试见 `MaliciousPublicKeyTest`：覆盖无 PoP / 错消息 PoP / 篡改 PoP、
经典 rogue-key 构造无法通过最终验证且无法注册、关联公钥（`−X_v`）替换
产生的部分签名无法通过校验。

### 3.2 随机数重用

服务端对随机数使用做持久化追踪：

- **承诺去重**：每个 `(R1,R2)` 元组只能绑定到一个
  `(会话, 轮次, 签名方)` 槽位。跨会话、跨轮次（含重启后）提交相同元组，
  返回 `DUPLICATE_COMMITMENT`；同一槽位重复提交完全相同的承诺视为幂等。
  同轮对同一签名方提交*不同*承诺也返回 `DUPLICATE_COMMITMENT`，要求 retry。
- **消费去重**：当某 `(R1,R2)` 元组的部分签名通过校验后，该元组被标记为已消费。
  同一元组用于另一消息时返回 `PARTIAL_SIGNATURE_REUSE`，
  与一般的 `INVALID_PARTIAL_SIGNATURE` 明确区分。
- 重用的随机数不会产生任何可用签名；私钥从不在服务端出现，因此重用攻击无法
  从服务端泄露私钥。
- 会话 retry 与崩溃恢复都会开启新轮次（round+1），旧随机数元组仍在
  持久化去重表中，无法被再次使用。

### 3.3 部分聚合冒充完整签名

服务只在收齐全部参与方的**有效**部分签名、且聚合结果通过最终验证后，
才把会话置为 `COMPLETED` 并保存聚合签名。任何未完成状态下调用
aggregate 都返回 `SESSION_INCOMPLETE`，绝不返回半成品。

## 4. 会话生命周期

状态机：

```
        create                收齐承诺+全部有效部分签名(且聚合验证通过)
  ───────────────►  OPEN  ───────────────────────────────────────► COMPLETED
                     │  ▲                                             │
         cancel      │  │ retry(仅 FAILED)                       不可取消
                     ▼  │
                  CANCELLED

  OPEN ──超时 / 重启恢复 / 连续无效部分签名达阈值──► FAILED ──cancel──► CANCELLED
```

- **超时**：`sweepTimeouts`（由 `TimeoutScheduler` 周期触发，或任意请求惰性触发）
  将过期 OPEN 会话置为 `FAILED(TIMEOUT)`。FAILED 可 retry 或 cancel。
- **无效部分签名**：累计达到 `multisig.max-invalid-attempts`（默认 3）
  才置 `FAILED(INVALID_SUBMISSION)`；之前保留 OPEN 以便重交正确签名。
- **重启恢复**：启动时 OPEN 会话默认置为
  `FAILED(RESTART_RECOVERY)` 并打 `recoveredAfterRestart` 标记，
  必须显式 retry 才会用新随机数继续；已 COMPLETED 会话不受影响，仍可验证。
- **retry**：round 加一，清空本轮承诺与部分签名、重置截止时间与失败计数，
  聚合公钥与参与方集合不变。语义确定、可解释。

## 5. 密钥轮换与撤销

- 轮换（`POST /api/keys/rotate`）原子地注册新密钥并撤销旧密钥；
  新会话只能使用新 `keyId`，旧密钥拒绝参与新会话（`KEY_REVOKED`）。
- 撤销（`POST /api/keys/{id}/revoke`）记录撤销时间与原因，可审计；
  撤销幂等。被撤销的公钥记录仍保留，历史聚合签名照常可验证。

## 6. 持久化与崩溃恢复

- 全部注册信息、PoP、会话状态、随机数承诺/消费记录保存在单个 JSON 文件
  （`multisig.state-file`，默认 `data/multisig-state.json`）。
- 每次变更在全局读写锁的写锁内更新，并以「写临时文件 + 原子 rename」落盘，
  崩溃不会留下半写文件；并发写不会互相覆盖。

## 7. 并发

- 全局 `ReentrantReadWriteLock` 串行化所有状态变更，读路径（视图、验证、查询）
  使用读锁。
- 同一 `keyId` 并发注册：第二次得到 `KEY_ALREADY_REGISTERED`，不覆盖。
- 并发注册与撤销最终状态确定且持久化；重复提交相同部分签名幂等。

## 8. 安全边界（不保证的内容）

- 不做网络身份认证 / 授权 / TLS；按需求仅本地使用。
- 不防范能够直接读写状态文件或进程内存的本地攻击者。
- 不提供签名方间的消息协商、参与方资格审核 UI（由调用方在创建会话时决定）。
- 确定性协议在两个参与方集合/消息不同的会话间使用不同挑战；
  但同一批参与方对同一消息可合法产生多个签名（不可链接性不是目标）。

## 9. 错误码

| 错误码 | HTTP | 含义 |
| --- | --- | --- |
| `KEY_NOT_FOUND` | 404 | 引用了未注册的 keyId |
| `KEY_ALREADY_REGISTERED` | 409 | keyId 已存在，注册不覆盖 |
| `KEY_REVOKED` | 409 | 密钥已撤销，不能参与新会话 |
| `INVALID_PUBLIC_KEY` | 400 | 公钥编码非法 / 不在曲线上 / 入参缺失 |
| `INVALID_PROOF_OF_POSSESSION` | 400 | 所有权证明缺失、格式错或验证失败 |
| `INVALID_NONCE_COMMITMENT` | 400 | 非承诺缺失或点编码非法（区别于真正的重用） |
| `SESSION_NOT_FOUND` | 404 | 会话不存在或创建入参非法 |
| `SESSION_NOT_OPEN` | 409 | 会话非 OPEN（已完成/取消/失败），拒绝提交 |
| `SESSION_INCOMPLETE` | 409 | 承诺或部分签名未收齐，不产生聚合签名 |
| `SESSION_EXPIRED` | 410 | 会话已超时失败 |
| `SESSION_NOT_CANCELLABLE` | 409 | 已完成会话不可取消 |
| `SESSION_NOT_RETRYABLE` | 409 | 仅 FAILED 会话可 retry |
| `NOT_A_PARTICIPANT` | 403 | 提交者不在会话参与方列表 |
| `PARTICIPANT_REVOKED` | 409 | 参与方在会话进行中被撤销 |
| `DUPLICATE_COMMITMENT` | 409 | 承诺重复 / 跨会话或跨轮重用随机数 / 同槽不同承诺 |
| `PARTIAL_SIGNATURE_REUSE` | 409 | 同一随机数元组被用于另一消息（跨消息重用） |
| `INVALID_PARTIAL_SIGNATURE` | 400 | 部分签名密码学校验失败或标量非法 |
| `SIGNATURE_VERIFICATION_FAILED` | 400 | 聚合签名最终一次性验证未通过 |
