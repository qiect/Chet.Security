using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Chet.Security;

/// <summary>DSA 数字签名工具类（遗留算法，仅做兼容使用；新项目建议改用 ECDSA 或 RSA-PSS）。</summary>
public static class DSAHelper
{
    private const string PublicLabel = "PUBLIC KEY";
    private const string PrivateLabel = "PRIVATE KEY";

    /// <summary>生成 DSA 密钥对并返回 PEM 字符串（公钥为 SubjectPublicKeyInfo，私钥为 PKCS#8 PrivateKeyInfo）。</summary>
    /// <param name="keySize">密钥位数，默认 1024（仅支持 1024/2048/3072；SHA-256withDSA 在 2048/3072 上为原生 N=256）。</param>
    /// <returns>公钥与私钥的 PEM 字符串。</returns>
    public static (string PublicKeyPem, string PrivateKeyPem) GenerateKeyPair(int keySize = 1024)
    {
        if (keySize != 1024 && keySize != 2048 && keySize != 3072)
            throw new ArgumentOutOfRangeException(nameof(keySize), "DSA keySize 仅支持 1024/2048/3072。");

        // DSA 需先产生域参数（p, q, g），再用域参数生成密钥对。
        var paramGen = new DsaParametersGenerator();
        paramGen.Init(keySize, 80, new SecureRandom());
        var dsaParams = paramGen.GenerateParameters();

        var keyGen = new DsaKeyPairGenerator();
        keyGen.Init(new DsaKeyGenerationParameters(new SecureRandom(), dsaParams));
        var pair = keyGen.GenerateKeyPair();

        var pubDer = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pair.Public).GetEncoded();
        var privDer = PrivateKeyInfoFactory.CreatePrivateKeyInfo(pair.Private).GetEncoded();
        return (PemEncode(pubDer, PublicLabel), PemEncode(privDer, PrivateLabel));
    }

    /// <summary>使用私钥 PEM 对数据签名，返回 Base64 签名（SHA-256withDSA）。</summary>
    /// <param name="data">待签名数据（UTF-8）。</param>
    /// <param name="privateKeyPem">PKCS#8 私钥 PEM。</param>
    /// <returns>Base64 签名。</returns>
    public static string Sign(string data, string privateKeyPem)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(data, nameof(data));
        CryptoPolyfill.ThrowIfNullOrEmpty(privateKeyPem, nameof(privateKeyPem));
        var privParam = ReadPrivateKey(privateKeyPem);
        var signer = SignerUtilities.GetSigner("SHA-256withDSA");
        signer.Init(true, privParam);
        var dataBytes = Encoding.UTF8.GetBytes(data);
        signer.BlockUpdate(dataBytes, 0, dataBytes.Length);
        return Convert.ToBase64String(signer.GenerateSignature());
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
        var pubParam = ReadPublicKey(publicKeyPem);
        var signer = SignerUtilities.GetSigner("SHA-256withDSA");
        signer.Init(false, pubParam);
        var dataBytes = Encoding.UTF8.GetBytes(data);
        signer.BlockUpdate(dataBytes, 0, dataBytes.Length);
        return signer.VerifySignature(Convert.FromBase64String(signatureBase64));
    }

    private static AsymmetricKeyParameter ReadPrivateKey(string pem)
    {
        var keyParam = ReadPem(pem) as AsymmetricKeyParameter;
        if (keyParam == null || !keyParam.IsPrivate)
            throw new CryptographicException("PEM 不是有效的 PKCS#8 私钥。");
        return keyParam;
    }

    private static AsymmetricKeyParameter ReadPublicKey(string pem)
    {
        var keyParam = ReadPem(pem) as AsymmetricKeyParameter;
        if (keyParam == null || keyParam.IsPrivate)
            throw new CryptographicException("PEM 不是有效的 SubjectPublicKeyInfo 公钥。");
        return keyParam;
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

    /// <summary>通过 BouncyCastle PemReader 读取 PEM 对象。</summary>
    /// <param name="pem">PEM 文本。</param>
    private static object ReadPem(string pem)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(pem, nameof(pem));
        var reader = new PemReader(new StringReader(pem));
        return reader.ReadObject() ?? throw new CryptographicException("PEM 内容为空或无法解析。");
    }
}
