

## 整体架构（三层）

客户端
  │
  ▼
┌─────────────────────────────┐
│  API Tier (API Gateway + Lambda + DynamoDB)  │
└──────────────┬──────────────┘
               │ (仅解密时走这条路)
               ▼
┌─────────────────────────────┐
│  Decryption Tier (NLB + EC2 Parent Instance) │
└──────────────┬──────────────┘
               │ vsock
               ▼
┌─────────────────────────────┐
│  Enclave Tier (Nitro Enclave)               │
└─────────────────────────────┘


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


## 各模块详解

### 1. API Tier — api/ 目录（Python）

| 组件 | 作用 |
|------|------|
| API Gateway | 对外暴露 REST API 入口（/v1/vaults） |
| Lambda | Python 编写，处理所有 CRUD 请求 |
| DynamoDB | 存储 vault 元数据（公钥、加密后的私钥、加密后的属性）和审计日志 |

对应文件：
- api/ — Lambda 函数代码（Python，使用 Powertools for AWS Lambda）
- api/template.yml — API 层的 SAM/CloudFormation 模板

### 2. Decryption Tier（Parent 父实例）— parent/ 目录（Rust）

| 组件 | 作用 |
|------|------|
| NLB | 网络负载均衡器，TLS 透传（不终止 TLS）到 EC2 |
| NGINX | 在 EC2 上监听 443 端口，终止 TLS 连接 |
| ACM for Nitro Enclaves | 自动为 NGINX 配置证书，私钥保存在 enclave 内 |
| Vsock Proxy | 在父实例上运行，将 vsock 流量转发到 AWS KMS |
| Parent Application | Rust 编写，从 IMDSv2 获取 IAM 凭证，通过 vsock 将解密请
求转发给 enclave，再将结果返回给 Lambda |

对应文件：
- parent/ — Parent 应用 Rust 源码
- vault_template.yml — EC2 实例、Auto Scaling Group、NLB 等基础设施定义

### 3. Enclave Tier — enclave/ 目录（Rust）

| 组件 | 作用 |
|------|------|
| kmstool-enclave-cli | 在 enclave 内使用 KMS 解密 secret key |
| Enclave Application | Rust 编写，先用 KMS 解密 data key，再用 data key 解密各
个加密属性，支持 CEL 表达式转换 |

对应文件：
- enclave/ — Enclave 应用 Rust 源码

### 4. 其他关键文件

| 文件/目录 | 作用 |
|-----------|------|
| Cargo.toml / Cargo.lock | Rust workspace 根配置（parent + enclave） |
| kms_template.yml | KMS 密钥的 CloudFormation 模板 |
| vpc_template.yml | VPC 网络基础设施模板 |
| deploy_template.yml | CI/CD 部署管道模板 |
| deploy.sh | 部署脚本 |
| docker-bake.hcl | Docker 构建配置（构建 enclave 镜像） |
| scripts/ | 辅助脚本 |
| docs/ | 文档源文件 |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


## 数据流转

### 创建钱包（Create Vault）— POST /v1/vaults

客户端 ──JSON请求──▶ API Gateway ──▶ Lambda
                                      │
                                      ├─1. 调用 KMS GenerateDataKeyPairWithoutPlaintext
                                      │   → 返回：公钥(明文) + 私钥(KMS加密的密文)
                                      │
                                      ├─2. 用公钥加密请求中的每个属性
                                      │   (如 first_name, ssn9, dob 等)
                                      │
                                      ├─3. 将以下内容存入 DynamoDB：
                                      │   • 公钥
                                      │   • 加密后的私钥（密文）
                                      │   • 每个属性的加密值
                                      │
                                      └─4. 返回 vault_id 给客户端


关键点：创建时不需要 enclave 参与，Lambda 直接用 KMS 生成的公钥加密数据。私钥的
明文从未出现过（WithoutPlaintext）。

### 解密钱包（Decrypt Vault）— POST /v1/vaults/{vault_id}/decrypt

客户端 ──请求──▶ API Gateway ──▶ Lambda
                                  │
                                  ├─1. 从 DynamoDB 读取加密的私钥 + 加密的属性
                                  │
                                  ├─2. 通过 NLB 发送 HTTPS 请求到 EC2 Parent
                                  │
                                  ▼
                              Parent (EC2)
                                  │
                                  ├─3. 从 IMDSv2 获取 IAM 临时凭证
                                  │
                                  ├─4. 将 {加密私钥 + 加密属性 + IAM凭证}
                                  │    通过 vsock 发送给 Enclave
                                  │
                                  ▼
                              Enclave (Nitro)
                                  │
                                  ├─5. 用 IAM 凭证调用 KMS Decrypt
                                  │    → 解密出私钥明文（仅存在于 enclave 内存中）
                                  │
                                  ├─6. 用私钥解密每个加密属性
                                  │
                                  ├─7. 如果有 CEL 表达式，执行转换
                                  │    (如 date(dob).age() 计算年龄)
                                  │
                                  └─8. 返回解密结果
                                       ▲
                                       │ vsock
                                  Parent ──▶ Lambda ──▶ API Gateway ──▶ 客户端


关键安全设计：
- 私钥明文只在 enclave 内存中短暂存在，enclave 没有持久存储、没有外部网络
- KMS 密钥策略通过 PCR 值（enclave 的度量值）限制只有特定 enclave 镜像才能调用
Decrypt
- Vsock Proxy 是 enclave 访问 KMS 的唯一网络通道
- NLB 做 TLS 透传，NGINX 在 EC2 上终止 TLS，保证 Lambda → EC2 之间的传输加密

References:
[1] AWS Nitro Enclaves Vault - Architecture - https://aws-samples.github.io/
sample-code-for-a-secure-vault-using-aws-nitro-enclaves/architecture/
[2] GitHub Repository - https://github.com/aws-samples/sample-code-for-a-secure
-vault-using-aws-nitro-enclaves
[3] AWS Nitro Enclaves Vault - User Guide - https://aws-samples.github.io/
sample-code-for-a-secure-vault-using-aws-nitro-enclaves/user-guide/