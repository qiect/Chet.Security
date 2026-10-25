using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.Threading.Tasks;

namespace Chet.Security;

/// <summary>RSA 非对称加密工具类：PEM（SubjectPublicKeyInfo 公钥 / PKCS#8 PrivateKeyInfo 私钥）密钥格式，OAEP-SHA256 加密、PSS-SHA256 签名，并支持长文本分块加解密。</summary>
public static class RSAHelper
{
    private const string PublicLabel = "PUBLIC KEY";
    private const string PrivateLabel = "PRIVATE KEY";
    private const string ChunkSeparator = "|||";
    private const string ChunkedSeparator = ".";

    /// <summary>生成 RSA 密钥对并返回 PEM 字符串（公钥为 SubjectPublicKeyInfo，私钥为 PKCS#8 PrivateKeyInfo）。</summary>
    /// <param name="keySize">密钥位数，默认 2048（须为 512~16384 之间 8 的倍数）。</param>
    /// <returns>公钥与私钥的 PEM 字符串。</returns>
    public static (string PublicKeyPem, string PrivateKeyPem) GenerateKeyPair(int keySize = 2048)
    {
        if (keySize < 512 || keySize > 16384 || keySize % 8 != 0)
            throw new ArgumentOutOfRangeException(nameof(keySize), "keySize 必须为 512~16384 之间 8 的倍数。");

        var generator = new RsaKeyPairGenerator();
        generator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), new SecureRandom(), keySize, 64));

        var pair = generator.GenerateKeyPair();
        var pubDer = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pair.Public).GetEncoded();
        var privDer = PrivateKeyInfoFactory.CreatePrivateKeyInfo(pair.Private).GetEncoded();
        return (PemEncode(pubDer, PublicLabel), PemEncode(privDer, PrivateLabel));
    }

    /// <summary>使用公钥 PEM 加密明文，返回 Base64 密文（OAEP-SHA256 填充）。</summary>
    /// <param name="plain">待加密明文。</param>
    /// <param name="publicKeyPem">SubjectPublicKeyInfo 格式的公钥 PEM。</param>
    /// <returns>Base64 密文；失败抛出 <see cref="CryptographicException"/>。</returns>
    public static string Encrypt(string plain, string publicKeyPem)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(plain, nameof(plain));
        CryptoPolyfill.ThrowIfNullOrEmpty(publicKeyPem, nameof(publicKeyPem));
        var cipher = Encrypt(Encoding.UTF8.GetBytes(plain), ToDerFromPem(publicKeyPem, true));
        return Convert.ToBase64String(cipher);
    }

    /// <summary>使用私钥 PEM 解密 Base64 密文，返回明文（OAEP-SHA256）。</summary>
    /// <param name="cipherBase64">Base64 编码的密文。</param>
    /// <param name="privateKeyPem">PKCS#8 PrivateKeyInfo 格式的私钥 PEM。</param>
    /// <returns>明文。</returns>
    public static string Decrypt(string cipherBase64, string privateKeyPem)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(cipherBase64, nameof(cipherBase64));
        CryptoPolyfill.ThrowIfNullOrEmpty(privateKeyPem, nameof(privateKeyPem));
        var plain = Decrypt(Convert.FromBase64String(cipherBase64), ToDerFromPem(privateKeyPem, false));
        return Encoding.UTF8.GetString(plain);
    }

    /// <summary>使用公钥 DER（SubjectPublicKeyInfo）加密原始字节，返回密文字节（OAEP-SHA256）。</summary>
    /// <param name="plain">待加密明文字节。</param>
    /// <param name="publicKeyDer">SubjectPublicKeyInfo 公钥 DER。</param>
    public static byte[] Encrypt(byte[] plain, byte[] publicKeyDer)
    {
        if (plain is null) throw new ArgumentNullException(nameof(plain));
        if (publicKeyDer is null) throw new ArgumentNullException(nameof(publicKeyDer));
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(publicKeyDer, out _);
        return rsa.Encrypt(plain, RSAEncryptionPadding.OaepSHA256);
    }

    /// <summary>使用私钥 DER（PKCS#8 PrivateKeyInfo）解密密文字节，返回明文字节（OAEP-SHA256）。</summary>
    /// <param name="cipher">密文字节。</param>
    /// <param name="privateKeyDer">PKCS#8 私钥 DER。</param>
    public static byte[] Decrypt(byte[] cipher, byte[] privateKeyDer)
    {
        if (cipher is null) throw new ArgumentNullException(nameof(cipher));
        if (privateKeyDer is null) throw new ArgumentNullException(nameof(privateKeyDer));
        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(privateKeyDer, out _);
        return rsa.Decrypt(cipher, RSAEncryptionPadding.OaepSHA256);
    }

    /// <summary>使用 SubjectPublicKeyInfo 的 Base64 形式公钥加密，返回 Base64 密文。</summary>
    /// <param name="plain">待加密明文。</param>
    /// <param name="publicKeyDerBase64">公钥 DER 的 Base64 字符串。</param>
    public static string EncryptWithDerBase64(string plain, string publicKeyDerBase64)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(plain, nameof(plain));
        CryptoPolyfill.ThrowIfNullOrEmpty(publicKeyDerBase64, nameof(publicKeyDerBase64));
        var cipher = Encrypt(Encoding.UTF8.GetBytes(plain), Convert.FromBase64String(publicKeyDerBase64));
        return Convert.ToBase64String(cipher);
    }

    /// <summary>使用私钥 PEM 对数据签名，返回 Base64 签名（PSS-SHA256）。</summary>
    /// <param name="data">待签名数据（UTF-8）。</param>
    /// <param name="privateKeyPem">PKCS#8 私钥 PEM。</param>
    /// <param name="hashAlgorithmName">哈希算法名，默认 SHA256。</param>
    public static string SignData(string data, string privateKeyPem, string hashAlgorithmName = "SHA256")
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(data, nameof(data));
        CryptoPolyfill.ThrowIfNullOrEmpty(privateKeyPem, nameof(privateKeyPem));
        var sig = SignData(Encoding.UTF8.GetBytes(data), ToDerFromPem(privateKeyPem, false), hashAlgorithmName);
        return Convert.ToBase64String(sig);
    }

    /// <summary>使用公钥 PEM 验证签名。</summary>
    /// <param name="data">原始数据。</param>
    /// <param name="signatureBase64">Base64 签名。</param>
    /// <param name="publicKeyPem">公钥 PEM。</param>
    /// <param name="hashAlgorithmName">哈希算法名，默认 SHA256。</param>
    public static bool VerifyData(string data, string signatureBase64, string publicKeyPem, string hashAlgorithmName = "SHA256")
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(data, nameof(data));
        CryptoPolyfill.ThrowIfNullOrEmpty(signatureBase64, nameof(signatureBase64));
        CryptoPolyfill.ThrowIfNullOrEmpty(publicKeyPem, nameof(publicKeyPem));
        return VerifyData(Encoding.UTF8.GetBytes(data), Convert.FromBase64String(signatureBase64), ToDerFromPem(publicKeyPem, true), hashAlgorithmName);
    }

    /// <summary>使用私钥 DER 对字节数据签名，返回签名字节（PSS）。</summary>
    /// <param name="data">待签名数据。</param>
    /// <param name="privateKeyDer">PKCS#8 私钥 DER。</param>
    /// <param name="hashAlgorithmName">哈希算法名，默认 SHA256。</param>
    public static byte[] SignData(byte[] data, byte[] privateKeyDer, string hashAlgorithmName = "SHA256")
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (privateKeyDer is null) throw new ArgumentNullException(nameof(privateKeyDer));
        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(privateKeyDer, out _);
        return rsa.SignData(data, new HashAlgorithmName(hashAlgorithmName), RSASignaturePadding.Pss);
    }

    /// <summary>使用公钥 DER 验证签名。</summary>
    /// <param name="data">原始数据。</param>
    /// <param name="signature">签名字节。</param>
    /// <param name="publicKeyDer">SubjectPublicKeyInfo 公钥 DER。</param>
    /// <param name="hashAlgorithmName">哈希算法名，默认 SHA256。</param>
    public static bool VerifyData(byte[] data, byte[] signature, byte[] publicKeyDer, string hashAlgorithmName = "SHA256")
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (signature is null) throw new ArgumentNullException(nameof(signature));
        if (publicKeyDer is null) throw new ArgumentNullException(nameof(publicKeyDer));
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(publicKeyDer, out _);
        return rsa.VerifyData(data, signature, new HashAlgorithmName(hashAlgorithmName), RSASignaturePadding.Pss);
    }

    /// <summary>对超长明文进行并行分块 RSA-OAEP-SHA256 加密，多个密文块以 <c>.</c> 连接，每段单独 Base64。各段在多核上并行处理，相比 <see cref="EncryptLong"/> 有显著性能提升。</summary>
    /// <param name="plain">待加密明文（任意长度）。</param>
    /// <param name="publicKeyPem">公钥 PEM。</param>
    /// <returns>形如 <c>base64_1.base64_2....</c> 的分块密文。</returns>
    /// <remarks>
    /// <para>分块版本利用多核 CPU 同时加密多个分段，在 4 核以上环境可提升 2~3 倍吞吐。</para>
    /// <para>性能提示：分块 RSA 加密长文本仍较慢（1MB 约 2~20 秒，视核数而定），且密文膨胀约 2.5 倍。
    /// 推荐使用 <see cref="HybridEncryptionHelper.RsaAesGcmEncrypt"/> 等混合加密方案（1MB 约 2~12ms）。</para>
    /// </remarks>
    public static string EncryptChunked(string plain, string publicKeyPem)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(plain, nameof(plain));
        CryptoPolyfill.ThrowIfNullOrEmpty(publicKeyPem, nameof(publicKeyPem));

        byte[] publicKeyDer = ToDerFromPem(publicKeyPem, true);
        int keySizeBytes;
        using (var rsa = RSA.Create())
        {
            rsa.ImportSubjectPublicKeyInfo(publicKeyDer, out _);
            keySizeBytes = rsa.KeySize / 8;
        }

        int chunkSize = keySizeBytes - 66;
        if (chunkSize <= 0)
            throw new CryptographicException($"密钥位数过小，无法用于 OAEP-SHA256 加密。");

        byte[] data = Encoding.UTF8.GetBytes(plain);
        if (data.Length == 0)
            return string.Empty;

        int chunkCount = (data.Length + chunkSize - 1) / chunkSize;
        var results = new string[chunkCount];

        Parallel.For(0, chunkCount, i =>
        {
            int offset = i * chunkSize;
            int len = Math.Min(chunkSize, data.Length - offset);
            byte[] chunk = data[offset..(offset + len)];
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(publicKeyDer, out _);
            byte[] cipher = rsa.Encrypt(chunk, RSAEncryptionPadding.OaepSHA256);
            results[i] = Convert.ToBase64String(cipher);
        });

        return string.Join(ChunkedSeparator, results);
    }

    /// <summary>并行解密 <see cref="EncryptChunked"/> 输出的分块密文，返回完整明文。各段在多核上并行处理。</summary>
    /// <param name="cipherBase64">由 <see cref="EncryptChunked"/> 产生的密文（多段以 <c>.</c> 连接的 Base64）。</param>
    /// <param name="privateKeyPem">私钥 PEM。</param>
    public static string DecryptChunked(string cipherBase64, string privateKeyPem)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(cipherBase64, nameof(cipherBase64));
        CryptoPolyfill.ThrowIfNullOrEmpty(privateKeyPem, nameof(privateKeyPem));

        byte[] privateKeyDer = ToDerFromPem(privateKeyPem, false);
        var chunks = cipherBase64.Split(new[] { ChunkedSeparator }, StringSplitOptions.None);
        if (chunks.Length == 0)
            throw new FormatException("分块密文格式无效：未找到有效分段。");
        var results = new byte[chunks.Length][];

        Parallel.For(0, chunks.Length, i =>
        {
            using var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(privateKeyDer, out _);
            results[i] = rsa.Decrypt(Convert.FromBase64String(chunks[i]), RSAEncryptionPadding.OaepSHA256);
        });

        int totalLength = 0;
        foreach (var r in results) totalLength += r.Length;
        var plainBytes = new byte[totalLength];
        int offset = 0;
        foreach (var r in results)
        {
            Buffer.BlockCopy(r, 0, plainBytes, offset, r.Length);
            offset += r.Length;
        }

        return Encoding.UTF8.GetString(plainBytes);
    }

    /// <summary>对超长明文进行分段 RSA-OAEP-SHA256 加密，多个密文块以 <c>|||</c> 连接，每段单独 Base64。</summary>
    /// <param name="plain">待加密明文（任意长度）。</param>
    /// <param name="publicKeyPem">公钥 PEM。</param>
    /// <returns>形如 <c>base64_1|||base64_2|||...</c> 的分段密文。</returns>
    /// <remarks>
    /// 性能提示：分段 RSA 加密长文本性能较差（1MB 约 5~55 秒），且密文膨胀约 2.5 倍。
    /// 推荐使用 <see cref="EncryptChunked"/>（并行分块，多核加速）或 <see cref="HybridEncryptionHelper.RsaAesGcmEncrypt"/>（混合加密，1MB 约 2~12ms）。
    /// </remarks>
    [Obsolete("建议使用 EncryptChunked（并行分块加解密，多核性能更优）或 HybridEncryptionHelper.RsaAesGcmEncrypt（混合加密，性能提升 3~4 个数量级）。")]
    public static string EncryptLong(string plain, string publicKeyPem)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(plain, nameof(plain));
        CryptoPolyfill.ThrowIfNullOrEmpty(publicKeyPem, nameof(publicKeyPem));
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(ToDerFromPem(publicKeyPem, true), out _);
        int keySizeBytes = rsa.KeySize / 8;
        int chunkSize = keySizeBytes - 66;
        if (chunkSize <= 0)
            throw new CryptographicException($"密钥位数 {rsa.KeySize} 过小，无法用于 OAEP-SHA256 加密。");
        var data = Encoding.UTF8.GetBytes(plain);
        if (data.Length == 0)
            return string.Empty;
        int chunkCount = (data.Length + chunkSize - 1) / chunkSize;
        int b64CipherLen = ((keySizeBytes + 2) / 3) * 4;
        int estimatedCapacity = chunkCount * (b64CipherLen + ChunkSeparator.Length);
        var sb = new StringBuilder(estimatedCapacity);
        for (int offset = 0; offset < data.Length; offset += chunkSize)
        {
            int len = Math.Min(chunkSize, data.Length - offset);
            var chunk = data[offset..(offset + len)];
            var cipher = rsa.Encrypt(chunk, RSAEncryptionPadding.OaepSHA256);
            if (sb.Length > 0) sb.Append(ChunkSeparator);
            sb.Append(Convert.ToBase64String(cipher));
        }
        return sb.ToString();
    }

    /// <summary>解密 <see cref="EncryptLong"/> 输出的分段密文，返回完整明文。</summary>
    /// <param name="cipherBase64">由 <see cref="EncryptLong"/> 产生的密文（多段以 <c>|||</c> 连接的 Base64）。</param>
    /// <param name="privateKeyPem">私钥 PEM。</param>
    [Obsolete("建议使用 DecryptChunked（并行分块解密，多核性能更优）或 HybridEncryptionHelper.RsaAesGcmDecrypt（混合解密）。")]
    public static string DecryptLong(string cipherBase64, string privateKeyPem)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(cipherBase64, nameof(cipherBase64));
        CryptoPolyfill.ThrowIfNullOrEmpty(privateKeyPem, nameof(privateKeyPem));
        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(ToDerFromPem(privateKeyPem, false), out _);
        int maxPlainPerChunk = rsa.KeySize / 8 - 66;
        var chunks = cipherBase64.Split(new[] { ChunkSeparator }, StringSplitOptions.RemoveEmptyEntries);
        int estimatedCapacity = chunks.Length * maxPlainPerChunk;
        using var ms = new MemoryStream(estimatedCapacity);
        foreach (var chunk in chunks)
        {
            var plain = rsa.Decrypt(Convert.FromBase64String(chunk), RSAEncryptionPadding.OaepSHA256);
            ms.Write(plain, 0, plain.Length);
        }
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    /// <summary>将 DER 字节数组按 64 字符每行封装为 PEM 文本。</summary>
    /// <param name="der">DER 编码字节。</param>
    /// <param name="label">PEM 标签，如 PUBLIC KEY / PRIVATE KEY。</param>
    private static string PemEncode(byte[] der, string label)
    {
        var sb = new StringBuilder();
        sb.Append("-----BEGIN ").Append(label).AppendLine("-----");
        var base64 = Convert.ToBase64String(der);
        for (int i = 0; i < base64.Length; i += 64)
        {
            int len = Math.Min(64, base64.Length - i);
            sb.AppendLine(base64.Substring(i, len));
        }
        sb.Append("-----END ").Append(label).AppendLine("-----");
        return sb.ToString();
    }

    /// <summary>通过 BouncyCastle PemReader 读取 PEM 对象（公钥返回 AsymmetricKeyParameter public，私钥返回 AsymmetricKeyParameter private）。</summary>
    /// <param name="pem">PEM 文本。</param>
    private static object ReadPem(string pem)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(pem, nameof(pem));
        var reader = new PemReader(new StringReader(pem));
        return reader.ReadObject() ?? throw new CryptographicException("PEM 内容为空或无法解析。");
    }

    /// <summary>从 PEM 中提取 DER 字节：先用 BC PemReader 解析为 AsymmetricKeyParameter，再按公开/私有方向重新编码为 SubjectPublicKeyInfo / PrivateKeyInfo DER。</summary>
    /// <param name="pem">PEM 文本。</param>
    /// <param name="isPublic">true=公钥；false=私钥。</param>
    private static byte[] ToDerFromPem(string pem, bool isPublic)
    {
        var keyParam = ReadPem(pem) as AsymmetricKeyParameter
            ?? throw new CryptographicException("PEM 不是有效的非对称密钥。");
        if (keyParam.IsPrivate == isPublic)
            throw new CryptographicException(isPublic ? "PEM 是私钥而非公钥。" : "PEM 是公钥而非私钥。");
        return isPublic
            ? SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyParam).GetEncoded()
            : PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyParam).GetEncoded();
    }
}