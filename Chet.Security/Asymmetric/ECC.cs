namespace Chet.Security;

/// <summary>ECDSA 数字签名与 ECDH 密钥协商工具类，基于 NIST P-256 曲线；密钥采用 SubjectPublicKeyInfo / PKCS#8 PEM 格式。</summary>
public static class ECCHelper
{
    private const string PublicLabel = "PUBLIC KEY";
    private const string PrivateLabel = "PRIVATE KEY";

    /// <summary>基于 NIST P-256 曲线生成 ECDSA 密钥对，返回 PEM 字符串（公钥 SubjectPublicKeyInfo，私钥 PKCS#8 PrivateKeyInfo）。</summary>
    /// <returns>公钥与私钥的 PEM 字符串。</returns>
    public static (string PublicKeyPem, string PrivateKeyPem) GenerateKeyPair()
    {
        // 直接使用 BCL 生成并导出 PKCS#8 / SubjectPublicKeyInfo，避免 BC 重新导出 EC 密钥时产生 BCL ImportPkcs8PrivateKey 不接受的非标准 DER。
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pubDer = ecdsa.ExportSubjectPublicKeyInfo();
        var privDer = ecdsa.ExportPkcs8PrivateKey();
        return (PemEncode(pubDer, PublicLabel), PemEncode(privDer, PrivateLabel));
    }

    /// <summary>使用私钥 PEM 对数据签名，返回 Base64 签名（SHA-256，ECDSA）。</summary>
    /// <param name="data">待签名数据（UTF-8）。</param>
    /// <param name="privateKeyPem">PKCS#8 私钥 PEM。</param>
    /// <returns>Base64 签名。</returns>
    public static string Sign(string data, string privateKeyPem)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(data, nameof(data));
        CryptoPolyfill.ThrowIfNullOrEmpty(privateKeyPem, nameof(privateKeyPem));
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportPkcs8PrivateKey(ToDerFromPem(privateKeyPem, false), out _);
        var sig = ecdsa.SignData(Encoding.UTF8.GetBytes(data), HashAlgorithmName.SHA256);
        return Convert.ToBase64String(sig);
    }

    /// <summary>使用公钥 PEM 验证签名。</summary>
    /// <param name="data">原始数据。</param>
    /// <param name="signatureBase64">Base64 签名。</param>
    /// <param name="publicKeyPem">公钥 PEM。</param>
    /// <returns>验证结果。</returns>
    public static bool Verify(string data, string signatureBase64, string publicKeyPem)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(data, nameof(data));
        CryptoPolyfill.ThrowIfNullOrEmpty(signatureBase64, nameof(signatureBase64));
        CryptoPolyfill.ThrowIfNullOrEmpty(publicKeyPem, nameof(publicKeyPem));
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(ToDerFromPem(publicKeyPem, true), out _);
        return ecdsa.VerifyData(Encoding.UTF8.GetBytes(data), Convert.FromBase64String(signatureBase64), HashAlgorithmName.SHA256);
    }

    /// <summary>使用 ECDH 协商共享密钥：先用 <see cref="ECDiffieHellman.DeriveKeyMaterial"/> 得到原始共享点（X 坐标），再经 SHA-256 派生为 32 字节密钥。</summary>
    /// <param name="privateKeyPem">本方 PKCS#8 私钥 PEM。</param>
    /// <param name="otherPartyPublicKeyPem">对方 SubjectPublicKeyInfo 公钥 PEM。</param>
    /// <returns>32 字节 SHA-256 派生密钥。</returns>
    public static byte[] DeriveSharedSecret(string privateKeyPem, string otherPartyPublicKeyPem)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(privateKeyPem, nameof(privateKeyPem));
        CryptoPolyfill.ThrowIfNullOrEmpty(otherPartyPublicKeyPem, nameof(otherPartyPublicKeyPem));

        using var ecdh = ECDiffieHellman.Create();
        ecdh.ImportPkcs8PrivateKey(ToDerFromPem(privateKeyPem, false), out _);

        // 对方公钥需经 ECDsa 解析为 ECParameters 后导入临时 ECDH，再取其 PublicKey 交给 DeriveKeyMaterial。
        using var other = ECDsa.Create();
        other.ImportSubjectPublicKeyInfo(ToDerFromPem(otherPartyPublicKeyPem, true), out _);
        var otherParams = other.ExportParameters(false);

        using var otherEcdh = ECDiffieHellman.Create();
        otherEcdh.ImportParameters(otherParams);
        var otherPubKey = otherEcdh.PublicKey;

        // netstandard2.1 仅 DeriveKeyMaterial(ECDiffieHellmanPublicKey) 返回原始共享点，统一用 SHA-256 派生 32 字节。
        var rawSecret = ecdh.DeriveKeyMaterial(otherPubKey);
        using var sha = SHA256.Create();
        return sha.ComputeHash(rawSecret);
    }

    /// <summary>将 DER 字节数组按 64 字符每行封装为 PEM 文本。</summary>
    /// <param name="der">DER 编码字节。</param>
    /// <param name="label">PEM 标签。</param>
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

    /// <summary>从 PEM 中提取 DER 字节：直接剥离 BEGIN/END 标记行后 Base64 解码，避免 BC 重新导出 EC 密钥时产生 BCL ImportPkcs8PrivateKey/ImportSubjectPublicKeyInfo 不接受的非标准 DER。</summary>
    /// <param name="pem">PEM 文本。</param>
    /// <param name="isPublic">true=公钥；false=私钥。</param>
    private static byte[] ToDerFromPem(string pem, bool isPublic)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(pem, nameof(pem));
        var expectedLabel = isPublic ? PublicLabel : PrivateLabel;
        var beginMarker = "-----BEGIN " + expectedLabel + "-----";
        var endMarker = "-----END " + expectedLabel + "-----";

        var normalized = pem.Replace("\r\n", "\n").Replace("\r", "\n");
        var beginIdx = normalized.IndexOf(beginMarker, StringComparison.Ordinal);
        if (beginIdx < 0)
            throw new CryptographicException($"PEM 缺少 BEGIN 标记 '{expectedLabel}'。");
        var bodyStart = beginIdx + beginMarker.Length;
        var endIdx = normalized.IndexOf(endMarker, bodyStart, StringComparison.Ordinal);
        if (endIdx < 0)
            throw new CryptographicException($"PEM 缺少 END 标记 '{expectedLabel}'。");

        var body = normalized.Substring(bodyStart, endIdx - bodyStart);
        var base64 = new StringBuilder();
        foreach (var line in body.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.Length > 0)
                base64.Append(trimmed);
        }

        try
        {
            return Convert.FromBase64String(base64.ToString());
        }
        catch (FormatException ex)
        {
            throw new CryptographicException("PEM Base64 解码失败。", ex);
        }
    }
}
