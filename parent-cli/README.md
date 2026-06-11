# parent-cli

`parent-cli` 是一个直接调用 parent HTTP 接口的示例 CLI。

当前和 root secret 相关的命令有 3 个：

- `generate-root-secret-ciphertext`
- `inject-root-secret-ciphertext`
- `run-root-secret`

## 前置条件

- parent 服务已经启动
- enclave 已经可用
- parent 所在环境具备对应的 KMS 权限

默认配置来自代码里的常量：

- `base_url`: `https://localhost:10001`
- `region`: `ap-southeast-1`
- `key_id`: `mrk-794e2c0173cd4848849739bf393a76b5`

如果你的环境不同，可以通过参数覆盖。

## 1. 生成 Root Secret Ciphertext

这个命令会调用 parent 的 `GenerateRootSecretCiphertext` 接口，由 enclave 内部生成 root secret，并返回对应的 `root_secret_ciphertext`。

最简用法：

```bash
cargo run -p parent-cli -- generate-root-secret-ciphertext
```

指定地址、KMS key 和 region：

```bash
cargo run -p parent-cli -- \
  --base-url https://localhost:10001 \
  generate-root-secret-ciphertext \
  --key-id mrk-xxxx \
  --region ap-southeast-1
```

命令成功后，终端会打印一行：

```text
root_secret_ciphertext: <hex-string>
```

后面的注入命令直接使用这个值。

## 2. 注入 Root Secret Ciphertext

这个命令会调用 parent 的 `InjectRootSecretCiphertext` 接口，把你保存的 `root_secret_ciphertext` 注入到 enclave。enclave 会在内部解密，并把 root secret 保存在内存里。

```bash
cargo run -p parent-cli -- \
  inject-root-secret-ciphertext \
  --root-secret-ciphertext <hex-string>
```

指定地址和 region：

```bash
cargo run -p parent-cli -- \
  --base-url https://localhost:10001 \
  inject-root-secret-ciphertext \
  --root-secret-ciphertext <hex-string> \
  --region ap-southeast-1
```

成功时会输出：

```text
inject_root_secret_ciphertext succeeded
```

## 3. 一步完成生成并注入

如果只是想快速准备好 root secret，可以直接用：

```bash
cargo run -p parent-cli -- run-root-secret
```

指定地址、KMS key 和 region：

```bash
cargo run -p parent-cli -- \
  --base-url https://localhost:10001 \
  run-root-secret \
  --key-id mrk-xxxx \
  --region ap-southeast-1
```

这个命令会先执行生成，再自动执行注入。

## 命令名和接口名对应关系

- CLI `generate-root-secret-ciphertext` 对应接口 `GenerateRootSecretCiphertext`
- CLI `inject-root-secret-ciphertext` 对应接口 `InjectRootSecretCiphertext`
- CLI `run-root-secret` 是前两个命令的组合封装
