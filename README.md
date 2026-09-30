# multisig-aggregation-java

本地多方签名聚合与验证服务（Spring Boot 3 / Java 17 / secp256k1 Schnorr / MuSig1 风格）。
多个签名方对同一消息分别产生部分签名，服务端将其聚合成**单个紧凑签名**，
由**聚合公钥一次性验证**，验证结果与逐一验证全部部分签名一致。单签时退化为普通 Schnorr。

协议假设、安全边界与全部错误码见 [`docs/SECURITY.md`](docs/SECURITY.md)。

## 本地运行

```bash
mvn -o spring-boot:run
# 或
mvn -o clean package && java -jar target/multisig-aggregation-java-1.0-SNAPSHOT.jar
```

可配置项（环境变量覆盖）：

| 配置 | 环境变量 | 默认 |
| --- | --- | --- |
| `multisig.store-dir` | `MULTISIG_DATA_DIR` | `data` |
| `multisig.session-ttl-seconds` | `MULTISIG_SESSION_TTL_SECONDS` | `300` |
| `multisig.max-attempts` | `MULTISIG_MAX_ATTEMPTS` | `5` |
| `multisig.sweep-millis` | `MULTISIG_SWEEP_MILLIS` | `5000` |

全部数据（公钥、会话、随机数账本、签名方材料、审计）保存在本地 `data/`，无外部依赖。

## HTTP 接口

| 方法与路径 | 说明 |
| --- | --- |
| `POST /api/keys/register` | 注册公钥，必须带 `popHex` 所有权证明 |
| `POST /api/keys/rotate` | 轮换密钥（旧 → SUPERSEDED，新 → ACTIVE） |
| `POST /api/keys/{keyId}/revoke` | 撤销密钥 |
| `GET  /api/keys/{keyId}` / `GET /api/keys?status=ACTIVE` | 查询公钥 |
| `POST /api/sessions` | 创建签名会话（固定参与方、消息、聚合公钥快照） |
| `POST /api/sessions/{id}/commitments` | 第一轮：提交承诺 |
| `POST /api/sessions/{id}/nonces` | 第二轮：公开随机数（含重用检测） |
| `POST /api/sessions/{id}/partials` | 第三轮：提交部分签名（收齐即聚合完成） |
| `POST /api/sessions/{id}/cancel` | 取消（不可重试） |
| `POST /api/sessions/{id}/retry` | 重试失败/超时会话（新会话、新随机数） |
| `GET  /api/sessions/{id}` | 查询会话状态 |
| `POST /api/aggregate/key` | 计算一组 keyId 的聚合公钥 |
| `POST /api/aggregate/{id}/finalize` | 显式聚合（缺额返回 SESSION_INCOMPLETE） |
| `POST /api/aggregate/verify` | 用聚合公钥验证最终签名 |
| `GET  /api/aggregate/{id}/partials-check` | 逐一验证全部部分签名 |
| `GET  /api/audit` | 查询可追溯审计事件 |

## 端到端约定

- 公钥/随机数为 33 字节压缩点 hex；签名为 65 字节（33 字节点 + 32 字节标量）hex。
- 三轮顺序由服务端状态机强制：承诺收集中 → 随机数收集中 → 部分签名收集中 → 完成。
- 会话响应里的 `saltHex` 用于客户端计算承诺；`aggregatePubHex` 为聚合公钥。
- 测试中的本地签名方 `LocalSigner` 演示了客户端如何生成密钥、PoP、承诺、随机数与部分签名，
  私钥仅保存在本地 `data/signers/`。

## 测试

```bash
mvn -o test
```

覆盖场景（共 23 个用例）：

- 密码学自检：Schnorr 签名/验证、PoP、单签退化、手工三方聚合
- 完整多方流程：聚合验证通过、与逐一验证一致、篡改消息失败、单签互通
- 恶意公钥：无 PoP/伪造 PoP 注册被拒、冒名注册被拒、经典 rogue-key 失效
- 随机数重用：冲突承诺、会话内重复、跨会话重用，错误码可区分
- 生命周期：离线超时、取消不可重试、失败重试成功、拒绝不完整聚合
- 轮换撤销：撤销不入新会、话、历史签名仍可验证、轮换产生新聚合公钥
- 并发：并发注册/多会话推进、重复注册与重复部分签名幂等
- 崩溃恢复：未完成会话重启后标记失效、重试完成、恢复动作可审计
- Web 层：错误码 HTTP 映射与单签 HTTP 全链路
