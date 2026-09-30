# multisig-aggregation-java

本地多方签名聚合与验证服务。多个签名方各自持有 P-256 Schnorr 密钥，对同一消息
产生 MuSig2 部分签名，服务将其聚合成单个紧凑签名 `(R, s)`，由聚合公钥一次性
验证。全程本地完成，不依赖任何外部服务或真实凭据。

安全设计、协议假设、安全边界与全部错误码见 [`docs/SECURITY.md`](docs/SECURITY.md)。

## 构建与运行

```bash
mvn spring-boot:run        # 启动服务，默认 http://localhost:8080
mvn test                   # 运行全部测试（32 个，含安全/恢复/并发场景）
```

状态默认持久化到 `data/multisig-state.json`（自动创建，可配置）。

## 关键配置（application.properties）

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `multisig.state-file` | `data/multisig-state.json` | 持久化状态文件 |
| `multisig.default-timeout-millis` | `300000` | 会话默认超时 |
| `multisig.max-invalid-attempts` | `3` | 连续无效部分签名几次后会话 FAILED |
| `multisig.sweep-interval-millis` | `5000` | 超时扫描周期 |
| `multisig.mark-incomplete-sessions-failed-on-startup` | `true` | 重启后进行中会话是否置失败 |

## 签名流程

1. **注册公钥**：签名方本地生成密钥，构造所有权证明（对
   `"pop:" + keyId + ":" + publicKeyHex` 的标准 Schnorr 签名）后注册。
2. **创建会话**：提交消息（hex）与参与方 keyId 列表；服务固定参与方集合并
   计算聚合公钥（字典序排序后的每密钥系数聚合）。
3. **提交承诺**：多方会话每方提交两个非承诺 `R1,R2`；单方会话只提交 `R1`。
4. **获取签名视图**：承诺收齐后 `GET .../view` 返回 `X, R, b, e` 等公开上下文。
5. **本地生成并提交部分签名**：签名方在本地用私钥与秘密随机数计算 `s_i`
   （秘密随机数用后即弃），提交到服务端；服务逐个做密码学验证。
6. **聚合与验证**：全部有效部分签名收齐后，服务求和得到 `(R,s)`，
   用聚合公钥做最终 `s·G = R + e·X` 校验，通过才置 COMPLETED。
   单方时聚合签名即标准 Schnorr 签名，可独立互通验证。

## REST 接口

- `POST /api/keys` 注册（body: `keyId, publicKeyHex, popSigHex, popMessageHex`）
- `POST /api/keys/rotate` 轮换
- `POST /api/keys/{keyId}/revoke` 撤销（body: `reason`）
- `GET /api/keys` / `GET /api/keys/{keyId}` 查询
- `POST /api/sessions` 创建会话
- `GET /api/sessions/{id}` 会话状态
- `POST /api/sessions/{id}/commitments` 提交非承诺
- `GET  /api/sessions/{id}/view` 签名视图
- `POST /api/sessions/{id}/partials` 提交部分签名（收齐后返回聚合签名）
- `POST /api/sessions/{id}/aggregate` 获取完整聚合签名（未完成则报错）
- `GET  /api/sessions/{id}/verify` 用聚合公钥验证
- `POST /api/sessions/verify` 独立验证任意 `(message, X, R, s)`
- `POST /api/sessions/{id}/cancel` 取消
- `POST /api/sessions/{id}/retry` FAILED 会话开启新一轮（新随机数）

所有二进制值均为十六进制字符串；公钥/点为 33 字节 SEC1 压缩编码，
标量为 32 字节。错误响应统一为 `{"code": "...", "message": "..."}`。

## 本地签名方（不暴露私钥）

服务端只处理公钥与公开承诺；真正的签名在签名方本地完成。核心类：

- `crypto.LocalSigner`：持有私钥，`newCommitment` 生成一次性随机数承诺，
  `signPartial(view)` 生成部分签名并消费随机数，`signStandard` 用于 PoP。
- 端到端用法可参考测试支撑类
  `src/test/java/.../tests/support/TestHarness.java`。

## 模块结构

- `crypto/`：P-256 群运算、Schnorr/MuSig2 原语、本地签名方。
- `domain/`：错误码、异常、会话/密钥状态与值对象。
- `store/`：JSON 原子持久化与随机数使用记录。
- `service/`：密钥管理、会话生命周期、崩溃恢复、超时扫描。
- `api/`：REST 控制器、DTO、全局错误处理。
