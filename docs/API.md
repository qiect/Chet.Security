# Chet.Security — API 文档（参考）

> 说明：下述 API 名称、签名与示例是对仓库中常见工具类的标准化说明。如实际实现方法名或命名空间不同，我可以根据代码库调整文档以完全匹配源码。

命名空间（示例）
- Chet.Security
  - Chet.Security.Hash (MD5)
  - Chet.Security.Encoding (Base64)
  - Chet.Security.Symmetric (AES, DES, TripleDES)
  - Chet.Security.Asymmetric (RSA)

1. MD5（Chet.Security.Hash.MD5Util）
- 说明：计算 MD5 摘要，常用于校验或非安全哈希场景（注意：MD5 不应用于密码存储/安全散列）
- 方法：
  - string ComputeHashHex(string input)
    - 参数：input — 要计算的字符串（默认 UTF-8 编码）
    - 返回：十六进制小写字符串（32 字符）
  - string ComputeHashHex(byte[] data)
    - 参数：data — 输入字节数组
    - 返回：十六进制字符串
- 示例：
```csharp
var hex = MD5Util.ComputeHashHex("hello");
```

2. Base64（Chet.Security.Encoding.Base64Util）
- 方法：
  - string EncodeToString(string plain, Encoding? enc = null)
    - 参数：plain — 明文字符串；enc — 可选字符编码（默认为 UTF-8）
    - 返回：Base64 字符串
  - string DecodeToString(string base64, Encoding? enc = null)
    - 参数：base64 — Base64 编码的字符串
    - 返回：解码后的字符串
  - byte[] Encode(byte[] bytes)
  - byte[] Decode(string base64)
- 示例：
```csharp
var b64 = Base64Util.EncodeToString("abc");
var raw = Base64Util.DecodeToString(b64);
```

3. AES（Chet.Security.Symmetric.AESUtil）
- 说明：对称加密（示例以 AES-CBC + PKCS7Padding）
- 常见约定：key 与 iv 均为字节数组或可由字符串转换为字节；AES-128 使用 16 字节 key，AES-256 使用 32 字节 key；IV 通常 16 字节。
- 方法（示例）：
  - string EncryptStringToBase64(string plainText, string key, string iv)
    - key/iv：以原始字节（长度要求）或以 hex/base64 表示的字符串；文档中示例使用原始 UTF-8 字符串（注意长度）
    - 返回：Base64 编码的密文
  - string DecryptStringFromBase64(string cipherBase64, string key, string iv)
    - 返回：解密得到的明文字符串
  - byte[] EncryptBytes(byte[] plain, byte[] key, byte[] iv)
  - byte[] DecryptBytes(byte[] cipher, byte[] key, byte[] iv)
- 示例：
```csharp
var cipherB64 = AESUtil.EncryptStringToBase64("hello", key, iv);
var plain = AESUtil.DecryptStringFromBase64(cipherB64, key, iv);
```

4. DES / TripleDES（Chet.Security.Symmetric.DESUtil / TripleDESUtil）
- DES：Key 8 字节，IV 8 字节（DES 已过时，不推荐用于安全场景）
- TripleDES（3DES）：Key 16 或 24 字节，IV 8 字节
- 方法同 AES：支持字符串到 Base64 的加/解密接口以及字节版接口。

5. RSA（Chet.Security.Asymmetric.RSAUtil）
- 说明：非对称加密与签名。常见导出格式：XML 或 PEM（PKCS#1/PKCS#8）。示例中提供 PEM 文本作为密钥表示。
- 方法（示例）：
  - (string publicKeyPem, string privateKeyPem) GenerateKeyPair(int keySize = 2048)
    - 返回：公钥 / 私钥 PEM 字符串
  - string EncryptWithPublic(string plainText, string publicKeyPem)
    - 使用公钥加密，返回 Base64 密文
  - string DecryptWithPrivate(string cipherBase64, string privateKeyPem)
    - 使用私钥解密
  - string SignData(string plainText, string privateKeyPem, HashAlgorithmName hash = HashAlgorithmName.SHA256)
    - 返回 Base64 签名
  - bool VerifySignature(string plainText, string signatureBase64, string publicKeyPem, HashAlgorithmName hash = HashAlgorithmName.SHA256)
- 示例：
```csharp
var (pub, pri) = RSAUtil.GenerateKeyPair(2048);
var cipher = RSAUtil.EncryptWithPublic("hello", pub);
var plain = RSAUtil.DecryptWithPrivate(cipher, pri);
var sig = RSAUtil.SignData("message", pri);
var ok = RSAUtil.VerifySignature("message", sig, pub);
```

错误处理与异常
- 各方法在接收到不合法参数（如 key/iv 长度错误、Base64 格式错误、秘钥格式不支持）时应抛出 ArgumentException 或 CryptographicException。
- 调用方应捕获异常并按业务需要处理。

序列化与密钥格式
- RSA 密钥可以使用 PEM（PKCS#1/PKCS#8）或 XML；库可能提供导入/导出两种格式的转换方法（如需要我可以添加导出 PEM/导入 PEM 的帮助函数示例）。

测试与示例
- 推荐为每个工具类编写单元测试（覆盖加/解密、边界条件、错误处理）。
- 仓库内 examples/UsageExample.cs 提供完整示范（见例子文件）。

如果你希望，我可以：
- 根据仓库实际代码生成本 API 文档（精确匹配类名和签名）
- 生成更详细的安全说明、测试用例以及 GitHub Actions CI 工作流（单元测试、静态分析）
