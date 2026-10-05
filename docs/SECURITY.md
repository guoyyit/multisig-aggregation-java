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

## 5. 会话生命周期

状态机：

```
COLLECTING_COMMITMENTS
   -> COMMITMENTS_FINALIZED（至少一个随机数公开后）
   -> COLLECTING_SIGNATURES（全部随机数到齐）
   -> COMPLETED（全部部分签名验证通过并聚合）

任一开放态 --(校验失败/重用)--> FAILED_RETRYABLE
任一开放态 --(显式取消)------> FAILED_CANCELLED（不可重试）
任一开放态 --(越过 deadline)--> EXPIRED（可重试）
任一开放态 --(显式标记离线)--> FAILED_RETRYABLE / OFFLINE（可重试）
```

- **离线（显式、可解释）**：`POST /api/sessions/{id}/offline`，请求体
  `{"keyId":"...","reason":"..."}`。由有权方显式声明某参与方离线，会话立即转为
  `FAILED_RETRYABLE`，`failureReason=OFFLINE`，审计写入 `SESSION_FAILED/reason=OFFLINE`
  且带上该 keyId。离线是显式终局原因：**一旦标记，之后越过 deadline 的超时扫描与查询
  都不会把它覆盖或改写成 TIMEOUT**。离线会话保持可重试，取消语义不变。
- **超时**：后台扫描（`SessionSweeper`，默认每 5 秒）和每次访问都会检查
  `deadlineMillis`；越过截止时间进入 `EXPIRED`，原因 `TIMEOUT`。
  离线与超时因此在会话查询结果与审计事件中都是两类可区分的失败原因。
- **无效承诺 / 随机数 / 部分签名**：进入 `FAILED_RETRYABLE`，`failureReason` 分别为
  `INVALID_COMMITMENT / INVALID_NONCE / INVALID_PARTIAL_SIGNATURE / NONCE_REUSE`。
- **取消**：显式 `POST /api/sessions/{id}/cancel` 进入 `FAILED_CANCELLED`，
  原因 `CANCELLED`，**不可重试**（语义确定）。
- **重试**：仅 `FAILED_RETRYABLE` / `EXPIRED` 可重试；重试创建**新会话**
  （`{id}-r{n}`，`retryOf` 指向上次，`attempt` 递增），使用全新盐与随机数，
  超过 `multisig.max-attempts`（默认 5）返回 `SESSION_NOT_RETRYABLE`。
- **幂等**：重复提交同一承诺/随机数/部分签名原样成功；对已完成会话重复提交已有的
  部分签名也幂等返回；提交冲突内容则失败。

## 6. 密钥轮换与撤销

- **所有权证明持久化与兼容**：注册（`POST /api/keys/register`）与轮换
  （`POST /api/keys/rotate`）校验通过的 PoP（对压缩公钥哈希的 Schnorr 签名）随注册
  记录**一并持久化**在 `data/keys/{keyId}.json` 的 `popHex` 字段中；密钥被轮换
  （`SUPERSEDED`）或撤销（`REVOKED`）后，其证明记录同样保留，可供事后查证。
  公钥查询响应与列表均含 `proofStatus` 与 `popHex`；另提供
  `GET /api/keys/{keyId}/proof` 返回 `{proofStatus, popHex, valid}`，
  其中 `valid` 是用持久化证明对对应公钥**重新验证**的结果，重启后同样可用。
- **证明状态 `proofStatus`**：
  - `PRESENT`：注册/轮换时提交并通过校验的证明；
  - `LEGACY_MISSING`：升级前已存在、不含证明字段的旧注册记录。服务**正常加载、不丢
    数据、不启动失败**；旧记录状态明确可解释，仍为原状态（如 `ACTIVE`）并可参与新会话，
    历史签名验证不受影响。对旧记录调用证明查证接口返回 `proofStatus=LEGACY_MISSING`、
    `valid=false`；
  - `NOT_APPLICABLE`：见下文“先撤销后注册”的撤销墓碑，从未存在公钥材料。
- **审计中的证明信息**：`KEY_REGISTERED` 事件 detail 含 `proofStatus=PRESENT` 与
  `popFingerprint=<SHA-256(popHex)>`，可事后核对每次注册/轮换提交的是哪一份证明；
  审计与持久化内容均**不含任何私钥材料**（PoP 本身只是公开的签名）。
- 轮换 `POST /api/keys/rotate`：旧密钥置 `SUPERSEDED`（记录 `replacedById`），
  新密钥以新 keyId 注册为 `ACTIVE`。新会话只能使用新集合，因此产生**新的聚合公钥**。
- 撤销 `POST /api/keys/{id}/revoke`：密钥置 `REVOKED`，不能再加入任何新会话
  （创建会话时即返回 `KEY_REVOKED`）。对尚不存在的 keyId 调用撤销会写入一条
  **撤销墓碑**（`status=REVOKED`、`proofStatus=NOT_APPLICABLE`、无公钥材料，
  审计 `KEY_REVOKED/tombstone=true`）。
- **并发交错的确定语义**（见第 8 节）：同一 keyId 注册与撤销任意顺序交错，最终状态
  与真实执行顺序一致——先注册后撤销最终为 `REVOKED`；**先撤销（墓碑）后注册必须被
  明确拒绝**（`KEY_REVOKED`），不会出现注册覆盖撤销、撤销丢失或半写入中间状态。
- **历史可验证性**：会话文件保存聚合公钥快照与最终签名；轮换/撤销只改密钥登记表，
  历史聚合签名仍可用快照聚合公钥独立验证（见 `KeyRotationRevocationTest`）。
- 所有注册/轮换/撤销/会话关键动作写入 `data/audit/events.jsonl`，可经
  `GET /api/audit` 追溯。

## 7. 崩溃恢复与持久化

- 公钥、会话、随机数账本、签名方材料、审计日志都落盘在 `multisig.store-dir`
  （默认 `./data`）。JSON 采用临时文件 + 原子 rename，避免半截文件覆盖。
- **临时残留清理**：每次启动 `FileStore.initialize()` 都会递归清理数据目录中所有
  `*.tmp-<uuid>` 中间文件（崩溃发生在原子 rename 之前时残留）。正式数据仅以
  `.json/.jsonl` 结尾，不受影响；长期运行与反复崩溃/重启都不会积累垃圾文件。
- **审计末行完整性**：崩溃可能在审计 `events.jsonl` 末尾留下未写完的半行。读取审计时
  这类残行**不再被静默丢弃**：`GET /api/audit` 返回
  `truncatedTrailingLines` 计数（Java API 为 `AuditLog.read().truncatedTrailingLines()`），
  历史完整事件保持完整可追溯。残行原始字节在下次审计写入前被移入
  `data/audit/quarantine/events-partial-*.raw` **明确隔离**，主日志恢复干净行边界，
  新事件不会与残行粘连；隔离文件数量同样计入该检测标记。若出现“非末尾”的损坏行，
  读取会直接报错以保留证据，而不是悄悄忽略。
- 重启时 `RecoveryService` 扫描全部会话，未终结会话一律转为 `FAILED_RETRYABLE`，
  但恢复原因按崩溃时刻是否已越过截止时间**区分**：
  - `now > deadlineMillis`：`failureReason=RECOVERY_TIMEOUT`（审计 detail
    `reason=RECOVERY_TIMEOUT, pastDeadline=true`）；
  - 尚未越期：`failureReason=RECOVERY_INTERRUPTED`（`pastDeadline=false`）。
  两类会话均可由用户决定重试；绝不会把已收集的部分签名当作完整签名返回。
- **恢复恰好一次**：恢复在每个进程启动时执行一次，同一进程内重复调用
  （`runRecovery`）不再产生任何 `SESSION_RECOVERED`/`RECOVERY_COMPLETE` 审计记录。
- 随机数账本跨重启保留，重试会话使用新 `sessionId` ⇒ 新随机数，杜绝跨重启重用。

## 8. 并发模型

- 每个 keyId、每个 sessionId 各有一把可重入锁，读-改-写串行化；
  注册/轮换/撤销另在一把**全局注册锁**内完成“查重 + 落盘”，配合单文件原子写，
  保证同一 keyId 注册/撤销任意交错的最终状态与真实执行顺序一致，且：
  - 先注册后撤销 → `REVOKED`；
  - 先撤销后注册 → 注册被 `KEY_REVOKED` 明确拒绝（撤销墓碑保留）；
  - 同一公钥材料以不同 keyId 并发注册时，**至多一个成功**，其余得到可区分的
    `DUPLICATE_PUBLIC_KEY`（区别于 keyId 冲突的 `DUPLICATE_KEY_ID`），
    同一公钥不会被登记两次。
- 交错结束后磁盘状态即最终状态，重启后加载结果与接口返回一致
  （见 `InterleaveDeterminismTest`，使用 `@RepeatedTest` 重复执行，结果确定）。
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
| `DUPLICATE_KEY_ID` | keyId 已存在但状态/内容冲突，或会话 ID 冲突 |
| `DUPLICATE_PUBLIC_KEY` | 同一公钥材料已以其他 keyId 注册（并发注册时除一个成功外均返回此码） |
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
| `PARTICIPANT_OFFLINE` | 参与方被显式标记为离线（保留码，离线标记不抛错，直接在会话状态中体现） |
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
