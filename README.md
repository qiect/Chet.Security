# Chet.Security

全面的 C# 安全与加密工具类库，覆盖国密（SM2/SM3/SM4）与国际化主流算法，多目标 `netstandard2.1` + `net8.0`。

## 简介

- **仓库描述**：安全与加密工具类库，哈希 / 对称加密 / 非对称加密 / 混合加密 / 密钥派生 / 编码 / 随机数 / 校验和
- **语言**：C#
- **目标**：为常见加密操作提供简单、易用、安全的统一封装 API，方便在业务代码中直接调用
- **当前版本**：1.1.1
- **目标框架**：`netstandard2.1`、`net8.0`
- **依赖**：[`BouncyCastle.Cryptography`](https://www.nuget.org/packages/BouncyCastle.Cryptography) 2.5.1（国密 SM2/SM3/SM4、SHA-3、Blake2、ChaCha20-Poly1305、Argon2 等算法内核）

## 主要功能

| 分类 | 覆盖算法 |
| --- | --- |
| 哈希 | MD5、SHA-1/256/384/512、SHA3-256/384/512、SM3、HMAC（MD5/SHA1/SHA256/SHA384/SHA512/SM3）、Blake2b/Blake2s |
| 对称加密 | AES（CBC/ECB/GCM）、DES、TripleDES、RC2、ChaCha20-Poly1305、SM4 |
| 非对称加密 | RSA（OAEP-SHA256 + PSS-SHA256）、DSA（SHA-256withDSA）、ECC（NIST P-256，ECDSA + ECDH）、SM2（C1C3C2） |
| 混合加密 | RSA+AES-256-GCM、RSA+AES-256-CBC、RSA+ChaCha20-Poly1305、SM2+AES-256-GCM、SM2+SM4-CBC、SM2+ChaCha20-Poly1305、ECIES（ECDH+AES-256-GCM）、ECIES（ECDH+ChaCha20-Poly1305） |
| 密钥派生 | PBKDF2、BCrypt 形态（底层 PBKDF2）、SCrypt、HKDF、Argon2id |
| 编码 | Hex、Base64（标准 + URL 安全）、Base32、Base58（Bitcoin 码表） |
| 随机数 | `SecureRandomHelper`（基于 `RandomNumberGenerator`，含口令/UUID 生成） |
| 校验和 | CRC32、CRC64、Adler-32 |
| 统一门面 | `SecurityHelper`（密钥规范化 / 随机数 / 格式转换）、`ISecurityService` + `SecurityService`（按 `CryptoAlgorithm` 分发） |

## 安装

```bash
dotnet add package Chet.Security --version 1.1.1
```

```powershell
Install-Package Chet.Security -Version 1.1.1
```

```xml
<PackageReference Include="Chet.Security" Version="1.1.1" />
```

## 快速示例

```csharp
using Chet.Security;

// ── 哈希 ──
string md5    = MD5Helper.ComputeHash("hello");
string sha256 = SHAHelper.ComputeSHA256("hello");
string sha3   = SHAHelper.ComputeSHA3_512("hello");
string sm3    = SM3Helper.ComputeHash("hello");
string hmac   = HMACHelper.ComputeHmacSHA256("data", "secret");
string blake2 = Blake2Helper.ComputeBlake2b("hello");

// ── 对称加密（字符串密钥自动规范化） ──
string cipher = AESHelper.Encrypt("plaintext", "password", "my-iv");
string plain  = AESHelper.Decrypt(cipher, "password", "my-iv");

string gcm = AESHelper.EncryptGCM("data", "key", "nonce");       // AES-GCM（AEAD）
string dec = AESHelper.DecryptGCM(gcm, "key", "nonce");

string sm4 = SM4Helper.Encrypt("plaintext", "password", "my-iv"); // 国密 SM4
string chacha = ChaCha20Poly1305Helper.Encrypt("data", "key", "nonce");

// ── 非对称加密 ──
var (rsaPub, rsaPriv) = RSAHelper.GenerateKeyPair(2048);          // 返回 PEM 字符串
string ct = RSAHelper.Encrypt("hello", rsaPub);
string pt = RSAHelper.Decrypt(ct, rsaPriv);
string sig = RSAHelper.SignData("payload", rsaPriv);
bool ok = RSAHelper.VerifyData("payload", sig, rsaPub);

string chunked = RSAHelper.EncryptChunked(longText, rsaPub);     // 并行分块加密（. 分隔）
string recovered = RSAHelper.DecryptChunked(chunked, rsaPriv);

var (sm2Pub, sm2Priv) = SM2Helper.GenerateKeyPair();              // 国密 SM2，Base64 密钥
string c = SM2Helper.Encrypt("hello", sm2Pub);

var (eccPub, eccPriv) = ECCHelper.GenerateKeyPair();             // NIST P-256
string es = ECCHelper.Sign("data", eccPriv);
bool ev = ECCHelper.Verify("data", es, eccPub);

// ── 混合加密（信封加密，长文本推荐） ──
string envelope = HybridEncryptionHelper.RsaAesGcmEncrypt("long text", rsaPub);
string decrypted = HybridEncryptionHelper.RsaAesGcmDecrypt(envelope, rsaPriv);

string sm2Envelope = HybridEncryptionHelper.Sm2Sm4Encrypt("国密混合", sm2Pub);  // 纯国密
string eciesEnv = HybridEncryptionHelper.EciesEncrypt("secret", eccPub);       // ECIES 前向安全

// ── 密钥派生 ──
byte[] salt = PBKDF2Helper.GenerateSalt(16);
byte[] key = PBKDF2Helper.DeriveBytes("password", salt, iterations: 20000);
string argon = Argon2Helper.DeriveHex("password", "salt");       // Argon2id
string hkdf = HKDFHelper.DeriveKeyHex("ikm", "salt", "context");

// 密码哈希（BCryptHelper 形态，底层 PBKDF2-HMAC-SHA256）
string hashed = BCryptHelper.HashPassword("password");
bool valid = BCryptHelper.VerifyPassword("password", hashed);

// ── 编码 / 校验和 ──
string hex = HexHelper.Encode(new byte[] { 0x01, 0x02 });
string crc32 = CRC32Helper.ComputeHash("hello");

// ── 统一门面 ──
string token = SecurityHelper.GenerateRandomBase64(32);
var service = new SecurityService(CryptoAlgorithm.SHA256);
string h = service.Encode("hello");  // 返回小写十六进制摘要
```

## 详细 API 文档

完整的 API 文档基于 Astro + Starlight 构建，部署在 GitHub Pages：

🔗 **[https://qiect.github.io/Chet.Security/](https://qiect.github.io/Chet.Security/)**

按算法分类组织（编码 / 哈希 / 对称加密 / 非对称加密 / 混合加密 / 密钥派生 / 随机数 / 校验和 / 统一门面），每个帮助类的方法都有签名、参数表、返回值与可运行示例。

## 项目结构

```
Chet.Security/
├── Chet.Security.slnx
├── Chet.Security/                  # 主库（netstandard2.1;net8.0）
│   ├── Chet.Security.csproj
│   ├── GlobalUsings.cs
│   ├── Polyfills.cs                # 跨目标 API 兼容层
│   ├── Enums.cs                    # KeyNormalizeMode / OutputFormat / CryptoAlgorithm
│   ├── SecurityHelper.cs          # 共享辅助（密钥规范化、随机数、格式转换）
│   ├── ISecurityService.cs        # 统一门面接口
│   ├── SecurityService.cs  # 按 CryptoAlgorithm 分发的默认实现
│   ├── Encoding/                   # Hex / Base64 / Base32 / Base58
│   ├── Hash/                       # MD5 / SHA / SM3 / HMAC / Blake2
│   ├── Symmetric/                  # AES / DES / TripleDES / RC2 / ChaCha20Poly1305 / SM4
│   ├── Asymmetric/                 # RSA / DSA / ECC / SM2
│   ├── Hybrid/                    # HybridEncryption（RSA+AES-GCM / SM2+SM4 / ECIES 等）
│   ├── KeyDerivation/             # PBKDF2 / BCrypt / SCrypt / HKDF / Argon2
│   ├── Random/                     # SecureRandom
│   └── Checksum/                   # CRC32 / CRC64 / Adler32
├── Chet.Security.Tests/            # xUnit 单元测试（300+ 项）
├── docs/                           # Astro Starlight 文档源码
└── .github/workflows/deploy.yml    # GitHub Pages 自动部署
```

## 设计原则与注意事项

- **命名空间**：所有帮助类统一在 `Chet.Security` 根命名空间下，文件夹仅做物理组织，避免与 BCL 的 `System.Text.Encoding` / `System.Random` / `HashAlgorithm` 等类型冲突。
- **命名约定**：静态帮助类一律 `XxxHelper`（如 `MD5Helper`、`AESHelper`、`RSAHelper`）。
- **密钥规范化**：对称加密的字符串重载通过 `SecurityHelper.NormalizeKey` 自动将任意长度密钥规范化为算法要求的固定长度（默认 `KeyNormalizeMode.Hash`，可切换为左右补零）。
- **多目标兼容**：`Polyfills.cs` 暴露 `CryptoPolyfill`，统一 `Convert.ToHexString` / `ArgumentException.ThrowIfNullOrEmpty` 等 API 在 `netstandard2.1` 与 `net8.0` 下的行为。
- **安全建议**：不要在生产中硬编码密钥；建议使用 `SecureRandomHelper` 或 `SecurityHelper.GenerateRandomBytes` 生成密钥，并通过 KeyVault / 操作系统密钥库妥善存储。MD5 / SHA-1 / DES / RC2 已不满足现代安全要求，仅作遗留兼容用途。

## 贡献

非常欢迎贡献：
- 提交 issue 报 bug、提特性需求
- 提交 PR（遵循仓库编码风格，新增方法请补 xUnit 测试与 .mdx 文档）

## 许可证

MIT License。详见 [LICENSE](./LICENSE)。

## 联系

文档 / 示例 / 自动化测试 / CI 工作流如有需求，欢迎提 issue 反馈。