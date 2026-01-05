# Chet.Security

轻量级的安全/加密工具集合（C#），包含常用的哈希、对称加密、非对称加密和编码工具的封装，便于在项目中快速使用常见加密操作。

简介
- 仓库描述：安全工具类，MD5、AES、DES、TripDes、Rsa、Base64
- 语言：C#
- 目标：为常见加密操作提供简单、易用、安全的封装 API，方便在业务代码中直接调用。

主要功能
- MD5：计算字符串或字节流的 MD5 摘要（以十六进制字符串输出）
- Base64：字符串与字节数组的 Base64 编码/解码
- AES（对称加密）：支持 AES-CBC（带 IV）常用场景，返回 Base64 编码密文
- DES / TripleDES：常规对称加密辅助方法
- RSA（非对称加密）：生成密钥对，公钥加密/私钥解密，签名/验签

快速开始

1) 从源码引用
- 克隆仓库并在解决方案中引用项目，或把源文件直接拷贝到你的项目中。
  git clone https://github.com/qiect/Chet.Security.git
  dotnet build

2) 以项目引用方式在你的 .NET 项目中使用
- 在你的 solution 中添加对 Chet.Security 项目的引用，或把该项目打包成 NuGet（如果需要我可以帮你写 .nuspec / .csproj 打包示例）。

示例（快速演示）
在 C# 程序中：
```csharp
using Chet.Security;
...
// MD5
var md5 = MD5Util.ComputeHashHex("hello world");

// Base64
var b64 = Base64Util.EncodeToString("hello");

// AES（示例 key/iv 必须按实现要求长度传入）
var key = "0123456789abcdef"; // 16 字节 (128-bit)
var iv = "abcdef9876543210";  // 16 字节
var cipher = AESUtil.EncryptStringToBase64("hello", key, iv);
var plain = AESUtil.DecryptStringFromBase64(cipher, key, iv);

// RSA
var (pubPem, priPem) = RSAUtil.GenerateKeyPair(2048);
var ct = RSAUtil.EncryptWithPublic("secret", pubPem);
var pt = RSAUtil.DecryptWithPrivate(ct, priPem);
```

详细 API 文档
见 docs/API.md（同仓库内）。该文档列出了各个工具类的主要方法、参数与返回值示例。

设计原则与注意事项
- 密钥长度与 IV：对称加密方法通常要求固定长度的 Key 与 IV（例如 AES-128 使用 16 字节 key）；文档中会标注每个方法的要求。
- 编码格式：为了方便存储/传输，库中对密文通常使用 Base64 表示；如果需要原始字节输出，也有相应方法（或可改写）。
- 安全建议：不要在生产中硬编码密钥；建议使用安全随机数生成密钥并妥善存储（如使用 KeyVault、操作系统密钥库等）。

贡献
非常欢迎贡献：
- 提交 issue 报 bug、提特性
- 提交 PR（遵循 repo 中的编码风格）
- 如需我帮助把 issue 拆成子任务/生成 PR 描述，也可以告诉我

许可证
仓库未指定许可证时请在使用前确认许可（建议 MIT）。需要我为仓库添加 LICENSE 文件可以告诉我你希望的许可证类型，我会生成对应文件并提交建议内容。

联系
如果你希望我为本仓库生成 README 的英文版本、自动化测试样例、或添加 CI（GitHub Actions）工作流，也可以告诉我具体要求，我会继续补全。
