# 多方签名聚合与验证服务：协议、安全边界与错误码

本服务在**本地**实现基于 secp256k1 的 MuSig1 风格两方/多方 Schnorr 签名聚合。
所有密码学运算、密钥与状态都在本机完成，不依赖任何外部服务，也不内置真实凭据
（测试用密钥由 `LocalSigner` 在本地随机生成并落盘）。

## 1. 密码学对象

- 曲线：secp256k1（BouncyCastle `bcprov-jdk18on`）。
- 点编码：33 字节压缩点，hex 表示为 66 个字符。
- 签名：65 字节 = 33 字节压缩随机数点 `R` + 32 字节大端标量 `s`，hex 为 130 个字符。
- 挑战哈希：`e = int(SHA256_tagged("BIP0340/challenge", R || X || m)) mod n`。
- 所有权证明（PoP）：对消息 `SHA256_tagged("multisig-pop/v1", X)` 的标准 Schnorr 签名。

> 说明：本服务为教学/审计友好的本地实现，采用“完整点 Schnorr”（而非 BIP-340 的 x-only
> 点），因此签名是 65 字节；验证端始终是本服务自身。单签场景下聚合签名就是对该消息的
> 普通完整点 Schnorr 签名，任何实现相同编码规则的本地验证端都可独立验证。

## 2. 协议流程（三轮承诺）

1. **注册公钥（带 PoP）**：`POST /api/keys/register`。服务端验证 PoP 后才接受公钥，
   并拒绝“同一公钥点换一个 keyId 重复注册”。
2. **创建会话**：`POST /api/sessions`。创建时要求所有参与方密钥均为 `ACTIVE`，
   并立即固定参与方集合、消息、会话盐 `salt` 与**聚合公钥快照**。
3. **第一轮 承诺**：每方提交 `c_i = H_tag("multisig-commitment/v1", sessionId || salt || R_i)`。
4. **第二轮 公开随机数**：每方公开 `R_i`，服务端校验：
   - `R_i` 与承诺一致（`NONCE_COMMITMENT_MISMATCH`）；
   - 同一会话内没有重复承诺/重复随机数点（`COMMITMENT_DUPLICATE` / `DUPLICATE_NONCE`）；
   - 该 keyId 从未在**其他会话**用过同一随机数点（`NONCE_REUSE`）。
   全部随机数到齐后会话进入 `COLLECTING_SIGNATURES`。
5. **第三轮 部分签名**：每方计算
   `s_i = k_i + e·a_i·x_i mod n`，其中
   - `X = Σ a_i·X_i`（聚合公钥，按压缩点字典序排序后计算系数），
   - `R = Σ R_i`，`e = H(R || X || m)`，
   - `a_i = H_tag("multisig-coefficient/v1", X_i || X_1||…||X_n)`。
   服务端即时验证 `s_i·G = R_i + e·a_i·X_i`。
6. **聚合**：`s = Σ s_i mod n`，最终签名 `(R, s)` 由聚合公钥 `X` **一次性**验证：
   `s·G = R + e·X`。只有收齐并验证通过全部部分签名才会产出聚合签名；
   任何缺额都返回 `SESSION_INCOMPLETE`，绝不暴露半成品。

**单签退化**：参与方只有一个时系数 `a = 1`、聚合公钥 `X = X_1`，流程退化为普通
Schnorr 签名，验证互通（见 `MultisigFlowTest.singleSignerFlowIsPlainSchnorrAndInteroperable`）。

## 3. 如何抵御恶意公钥攻击

经典 rogue-key 攻击：攻击者取 `X_rogue = g·x' − X_victim`，在朴素 `X = Σ X_i` 的方案里
让聚合公钥退化为自己控制的密钥。本服务用两道独立防线：

1. **KeyAgg 系数绑定**：每个公钥的系数 `a_i` 依赖“全部参与方公钥的有序集合”。
   攻击者一旦调整自己的公钥，受害者和自己的系数都会改变，无法把受害者项消成可控形式。
2. **强制所有权证明（PoP）**：注册必须提供对应私钥对该公钥的 Schnorr 证明；
   “以他人公钥注册”“构造关联公钥”“提交欺诈公钥”都会在注册期被拒。

因此攻击者在拿不到受害者针对该消息的真实部分签名时，无法伪造通过聚合验证的签名。
对应测试：`RogueKeyAttackTest`。

## 4. 如何防止随机数重用

- 每个会话有唯一 `sessionId` 与会话盐；`LocalSigner` 的随机数由持久化种子与
  `sessionId` 派生（`multisig-signer-nonce/v1`），不同会话必然不同，重启后可复现同一
  会话的随机数以完成重试。
- 服务端维护**持久化随机数账本**（`data/nonces/{keyId}.json`），记录每个 keyId 用过的
  随机数点指纹。跨会话重用在公开随机数阶段即被 `NONCE_REUSE` 拒绝。
- 任何重用/冲突都会把会话置为失败态，**不产生可用签名**；由于部分签名在服务端即时验证，
  重用尝试不会推进到聚合阶段，也不会泄露私钥。

## 5. 会话生命周期与失败原因

状态机：

```
COLLECTING_COMMITMENTS
   -> COMMITMENTS_FINALIZED（至少一个随机数公开后）
   -> COLLECTING_SIGNATURES（全部随机数到齐）
   -> COMPLETED（全部部分签名验证通过并聚合）

任一开放态 --(校验失败/重用)--> FAILED_RETRYABLE
任一开放态 --(显式取消)------> FAILED_CANCELLED（不可重试）
任一开放态 --(越过 deadline)--> EXPIRED（可重试）
任一开放态 --(显式标记离线)--> FAILED_RETRYABLE（原因 OFFLINE，可重试）
```

- **离线 / 超时区分**：两类停滞原因可区分且互不覆盖——
  - **超时**：后台扫描（`SessionSweeper`，默认每 5 秒）和每次访问都会检查
    `deadlineMillis`；越过截止时间进入 `EXPIRED`，原因 `TIMEOUT`。
  - **离线**：`POST /api/sessions/{id}/offline`（请求体 `{"keyId","reason"}`）把开放中
    会话显式置为 `FAILED_RETRYABLE`，原因 `OFFLINE`，并写入 `SESSION_OFFLINE` 审计
    （含参与方 keyId）。离线判定只来自该显式入口，服务不擅自猜测网络状态。
  - 已标记 OFFLINE 的会话不再是开放态，随后的超时扫描**不会改写**其原因；
    已超时终结的会话再标记离线会被 `SESSION_NOT_ACTIVE` 拒绝，反之亦然，
    两类原因始终保持可区分。重复标记同一离线状态幂等，只产生一条审计。
- **无效承诺 / 随机数 / 部分签名**：进入 `FAILED_RETRYABLE`，`failureReason` 分别为
  `INVALID_COMMITMENT / INVALID_NONCE / INVALID_PARTIAL_SIGNATURE / NONCE_REUSE`。
- **取消**：显式 `POST /api/sessions/{id}/cancel` 进入 `FAILED_CANCELLED`，
  原因 `CANCELLED`，**不可重试**（语义确定）。
- **重试**：仅 `FAILED_RETRYABLE`（含 OFFLINE）/ `EXPIRED` 可重试；重试创建**新会话**
  （`{id}-r{n}`，`retryOf` 指向上次，`attempt` 递增），使用全新盐与随机数，
  超过 `multisig.max-attempts`（默认 5）返回 `SESSION_NOT_RETRYABLE`。
- **幂等**：重复提交同一承诺/随机数/部分签名原样成功；对已完成会话重复提交已有的
  部分签名也幂等返回；提交冲突内容则失败。
- **查询与审计**：会话查询结果中的 `failureReason` 与审计事件（`SESSION_OFFLINE` /
  `SESSION_EXPIRED` / `SESSION_FAILED` / `SESSION_RECOVERED`）给出可区分的失败原因。

## 6. 密钥轮换与撤销

- 轮换 `POST /api/keys/rotate`：旧密钥置 `SUPERSEDED`（记录 `replacedById`），
  新密钥以新 keyId 注册为 `ACTIVE`。新会话只能使用新集合，因此产生**新的聚合公钥**。
- 撤销 `POST /api/keys/{id}/revoke`：密钥置 `REVOKED`，不能再加入任何新会话
  （创建会话时即返回 `KEY_REVOKED`）。
- **历史可验证性**：会话文件保存聚合公钥快照与最终签名；轮换/撤销只改密钥登记表，
  历史聚合签名仍可用快照聚合公钥独立验证（见 `KeyRotationRevocationTest`）。
- 所有注册/轮换/撤销/会话关键动作写入 `data/audit/events.jsonl`，可经
  `GET /api/audit` 追溯。

### 6.1 所有权证明（PoP）的持久化与兼容

- 注册与轮换时提交的 PoP 随公钥记录一并持久化（`popHex` 字段），被轮换
  （`SUPERSEDED`）或被撤销（`REVOKED`）的密钥同样保留其证明记录。
- 重启后可经 `GET /api/keys/{keyId}/pop` 取回历史上提交的证明，响应中的
  `valid` 字段是服务端用该证明对当前记录公钥**即时重验**的结果；
  调用方也可自行用 `Schnorr.verifyPop` 规则独立重验。
- 公钥查询视图中的 `popStatus` 标明证明状态：`PRESENT`（已持久化证明）或
  `LEGACY_MISSING`（升级前写入的旧记录不含证明）。
- **旧数据兼容**：升级前已存在的注册记录没有 `popHex` 字段，服务照常加载，
  不启动失败、不丢数据；这些记录保持 `ACTIVE` 可参与新会话，历史签名验证不受影响，
  其 `popStatus=LEGACY_MISSING` 是明确可解释的正常状态。
- 注册/轮换的审计事件（`KEY_REGISTERED` / `KEY_ROTATED`）在 `detail` 中携带
  当时提交的 `pop=` 证明，便于事后核对；PoP 是对公钥的 Schnorr 签名，属于公开材料，
  审计**不含任何私钥**。

## 7. 崩溃恢复与持久化

- 公钥、会话、随机数账本、签名方材料、审计日志都落盘在 `multisig.store-dir`
  （默认 `./data`）。JSON 采用临时文件 + 原子 rename，避免半截文件覆盖。
- 重启时 `RecoveryService` 扫描全部会话，把未终结会话按**是否已越过截止时间**
  区分恢复原因：
  - 已越过 `deadlineMillis`：按超时处理为 `EXPIRED / TIMEOUT`，审计 `SESSION_EXPIRED`
    （`detail` 含 `trigger=recovery`）；
  - 未越过：按崩溃中断处理为 `FAILED_RETRYABLE / RECOVERY_ABORTED`，
    审计 `SESSION_RECOVERED`。
  两类恢复原因在会话查询与审计中都可区分，恢复后的会话均可重试；
  绝不会把已收集的部分签名当作完整签名返回。
- **恢复幂等**：恢复以会话终态为锚点，同一会话只会被转换并审计一次；
  重复执行恢复动作或反复重启不会产生重复审计记录。
- **临时文件清理**：异常退出可能在数据目录留下 `*.tmp-*` 中间文件；
  服务启动时自动扫描并删除这些残留（原子写入保证目标文件始终是完整版本，
  残留临时文件一定是未完成的中间产物），长期运行与反复崩溃不会积累垃圾文件。
- **审计完整性**：审计日志按行追加。崩溃可能留下未写完整的末行——读取审计时
  不完整行不会静默丢弃，而是计入 `GET /api/audit` 响应的 `corruptedLines`
  （`AuditLog.readAll()` 同样暴露该计数），完整历史事件保持可追溯。
- 随机数账本跨重启保留，重试会话使用新 `sessionId` ⇒ 新随机数，杜绝跨重启重用。

## 8. 并发模型

- 每个 keyId、每个 sessionId 各有一把可重入锁，读-改-写串行化，
  保证同一 keyId 的注册/撤销不会相互覆盖。
- 另有一把**全局注册锁**保护“检查公钥唯一性 + 写入新记录”的临界区，
  锁序固定为 keyId 锁 → 全局注册锁，持锁期间不再获取其他锁，无死锁。
- **交错确定性语义**：
  - 同一 keyId 的注册与撤销按真实执行顺序生效：先注册后撤销得到 `REVOKED`；
    先撤销（keyId 不存在）则撤销被 `KEY_NOT_FOUND` 明确拒绝，后续注册正常成功；
    撤销完成后再用同 keyId 注册被 `DUPLICATE_KEY_ID` 拒绝——注册不得覆盖撤销，
    撤销不会丢失，也不会出现半写入中间状态。
  - 同一公钥材料以不同 keyId 并发注册时至多一个成功，其余得到可区分的
    `DUPLICATE_PUBLIC_KEY`；同一公钥绝不会被登记两次。
  - 并发结束后重启服务，磁盘上的最终状态与接口返回的状态一致
    （见 `ConcurrencyDeterminismTest`）。
- 随机数账本使用全局短锁保证“检查-登记”原子性。
- 原子文件写入使用唯一临时文件名，避免同线程并发写互相踩踏。

## 9. 错误码含义

| 错误码 | 含义 |
| --- | --- |
| `VALIDATION_ERROR` | 请求参数非法（空值、ID 格式、重复参与方等） |
| `INVALID_PUBLIC_KEY` | 公钥 hex 无法解析或点不在曲线上 |
| `POP_MISSING` | 注册/轮换缺少所有权证明 |
| `POP_INVALID` | 所有权证明验证失败（未掌握对应私钥） |
| `KEY_NOT_FOUND` | 公钥不存在（HTTP 404） |
| `DUPLICATE_KEY_ID` | keyId 已存在（含已撤销记录）、会话 ID 冲突 |
| `DUPLICATE_PUBLIC_KEY` | 同一公钥已以其他 keyId 注册（与 keyId 冲突可区分） |
| `KEY_REVOKED` | 公钥已撤销，不能参与新会话 |
| `KEY_SUPERSEDED` | 公钥已被轮换取代 |
| `INVALID_MESSAGE` | 消息为空或不是合法 hex |
| `SESSION_NOT_FOUND` | 会话不存在（HTTP 404） |
| `SESSION_NOT_ACTIVE` | 当前会话状态不接受该操作 |
| `SESSION_ALREADY_FINALIZED` | 承诺阶段已结束，不能再修改参与集合 |
| `UNKNOWN_PARTICIPANT` | 提交方不属于本会话 |
| `COMMITMENT_DUPLICATE` | 会话内相同/冲突承诺（随机数重用迹象） |
| `NONCE_COMMITMENT_MISMATCH` | 公开随机数与之前承诺不一致 |
| `DUPLICATE_NONCE` | 会话内出现重复随机数点 |
| `NONCE_REUSE` | 同一 keyId 跨会话/跨消息重用随机数 |
| `INVALID_PARTIAL_SIGNATURE` | 部分签名编码或验证失败 |
| `SESSION_INCOMPLETE` | 仍有参与方未提交，拒绝产出聚合签名 |
| `SESSION_NOT_READY` | 尚未进入可提交部分签名的阶段 |
| `SESSION_NOT_RETRYABLE` | 会话状态不允许重试，或超过最大重试次数 |
| `SESSION_EXPIRED` | 会话已超时（HTTP 410） |
| `CONCURRENT_UPDATE` | 并发更新冲突（HTTP 409） |
| `INTERNAL_ERROR` | 持久化等内部错误 |

## 10. 安全边界与假设

- 本服务**不提供**网络传输安全：默认绑定本机，假定调用方与服务端处于同一可信主机；
  若跨机部署需自行加 mTLS/鉴权，这超出本服务范围。
- 信任本地文件系统与进程边界；能写 `data/` 目录者可篡改状态，部署时应限制目录权限。
- 采用承诺式三轮 MuSig1，假设签名方在全部承诺收集后才公开随机数；
  服务端通过状态机强制该顺序。
- 随机数“唯一性”由签名方种子派生 + 服务端账本共同保证；若攻击者直接控制签名方私钥文件，
  则等同于密钥泄露，不在威胁模型内。
- 不实现 BIP-340 x-only 互操作、不实现批量验证或 Taproot 密钥调整。
