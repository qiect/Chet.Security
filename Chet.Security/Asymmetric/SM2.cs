using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Chet.Security;

/// <summary>SM2 国密非对称加密与签名工具类（曲线 sm2p256v1，加密模式 C1C3C2，默认用户 ID "1234567812345678"）。</summary>
public static class SM2Helper
{
    private const string CurveName = "sm2p256v1";
    private const string DefaultUserId = "1234567812345678";

    /// <summary>生成 SM2 密钥对，公钥为未压缩点编码（65 字节，含 0x04 前缀）的 Base64，私钥为 32 字节标量的 Base64。</summary>
    /// <returns>(公钥 Base64, 私钥 Base64)。</returns>
    public static (string PublicKeyBase64, string PrivateKeyBase64) GenerateKeyPair()
    {
        var domain = GetDomain();
        var keyGen = new ECKeyPairGenerator();
        keyGen.Init(new ECKeyGenerationParameters(domain, new SecureRandom()));
        var pair = keyGen.GenerateKeyPair();

        var pubQ = ((ECPublicKeyParameters)pair.Public).Q;
        var privD = ((ECPrivateKeyParameters)pair.Private).D;
        var pubBytes = pubQ.GetEncoded(false);
        var privBytes = privD.ToByteArrayUnsigned();
        return (Convert.ToBase64String(pubBytes), Convert.ToBase64String(privBytes));
    }

    /// <summary>使用公钥加密明文，返回 Base64 密文（SM2 模式 C1C3C2）。</summary>
    /// <param name="plain">待加密明文。</param>
    /// <param name="publicKeyBase64">公钥 Base64（未压缩点，65 字节）。</param>
    /// <returns>Base64 密文。</returns>
    public static string Encrypt(string plain, string publicKeyBase64)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(plain, nameof(plain));
        CryptoPolyfill.ThrowIfNullOrEmpty(publicKeyBase64, nameof(publicKeyBase64));
        var pubParam = BuildPublicKeyParam(Convert.FromBase64String(publicKeyBase64));
        var cipher = EncryptBytes(Encoding.UTF8.GetBytes(plain), pubParam);
        return Convert.ToBase64String(cipher);
    }

    /// <summary>使用私钥解密 Base64 密文，返回明文（SM2 模式 C1C3C2）。</summary>
    /// <param name="cipherBase64">Base64 密文。</param>
    /// <param name="privateKeyBase64">私钥 Base64（32 字节标量）。</param>
    /// <returns>明文。</returns>
    public static string Decrypt(string cipherBase64, string privateKeyBase64)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(cipherBase64, nameof(cipherBase64));
        CryptoPolyfill.ThrowIfNullOrEmpty(privateKeyBase64, nameof(privateKeyBase64));
        var privParam = BuildPrivateKeyParam(Convert.FromBase64String(privateKeyBase64));
        var plain = DecryptBytes(Convert.FromBase64String(cipherBase64), privParam);
        return Encoding.UTF8.GetString(plain);
    }

    /// <summary>使用私钥对数据签名，返回 Base64 签名（SM2，默认用户 ID "1234567812345678"）。</summary>
    /// <param name="data">待签名数据（UTF-8）。</param>
    /// <param name="privateKeyBase64">私钥 Base64。</param>
    /// <param name="userId">用户 ID，默认 "1234567812345678"。</param>
    /// <returns>Base64 签名。</returns>
    public static string Sign(string data, string privateKeyBase64, string userId = DefaultUserId)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(data, nameof(data));
        CryptoPolyfill.ThrowIfNullOrEmpty(privateKeyBase64, nameof(privateKeyBase64));
        CryptoPolyfill.ThrowIfNullOrEmpty(userId, nameof(userId));
        var privParam = BuildPrivateKeyParam(Convert.FromBase64String(privateKeyBase64));
        var signer = new SM2Signer();
        signer.Init(true, new ParametersWithID(privParam, Encoding.ASCII.GetBytes(userId)));
        var dataBytes = Encoding.UTF8.GetBytes(data);
        signer.BlockUpdate(dataBytes, 0, dataBytes.Length);
        return Convert.ToBase64String(signer.GenerateSignature());
    }

    /// <summary>使用公钥验证签名（默认用户 ID "1234567812345678"）。</summary>
    /// <param name="data">原始数据。</param>
    /// <param name="signatureBase64">Base64 签名。</param>
    /// <param name="publicKeyBase64">公钥 Base64。</param>
    /// <param name="userId">用户 ID，默认 "1234567812345678"。</param>
    /// <returns>验证结果。</returns>
    public static bool Verify(string data, string signatureBase64, string publicKeyBase64, string userId = DefaultUserId)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(data, nameof(data));
        CryptoPolyfill.ThrowIfNullOrEmpty(signatureBase64, nameof(signatureBase64));
        CryptoPolyfill.ThrowIfNullOrEmpty(publicKeyBase64, nameof(publicKeyBase64));
        CryptoPolyfill.ThrowIfNullOrEmpty(userId, nameof(userId));
        var pubParam = BuildPublicKeyParam(Convert.FromBase64String(publicKeyBase64));
        var signer = new SM2Signer();
        signer.Init(false, new ParametersWithID(pubParam, Encoding.ASCII.GetBytes(userId)));
        var dataBytes = Encoding.UTF8.GetBytes(data);
        signer.BlockUpdate(dataBytes, 0, dataBytes.Length);
        return signer.VerifySignature(Convert.FromBase64String(signatureBase64));
    }

    private static byte[] EncryptBytes(byte[] plain, ECPublicKeyParameters pubParam)
    {
        var engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        engine.Init(true, new ParametersWithRandom(pubParam, new SecureRandom()));
        return engine.ProcessBlock(plain, 0, plain.Length);
    }

    private static byte[] DecryptBytes(byte[] cipher, ECPrivateKeyParameters privParam)
    {
        var engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        engine.Init(false, privParam);
        return engine.ProcessBlock(cipher, 0, cipher.Length);
    }

    private static ECPublicKeyParameters BuildPublicKeyParam(byte[] pubBytes)
    {
        var domain = GetDomain();
        var q = domain.Curve.DecodePoint(pubBytes);
        return new ECPublicKeyParameters(q, domain);
    }

    private static ECPrivateKeyParameters BuildPrivateKeyParam(byte[] privBytes)
    {
        var domain = GetDomain();
        var d = new BigInteger(1, privBytes);
        return new ECPrivateKeyParameters(d, domain);
    }

    private static ECDomainParameters GetDomain()
    {
        var x9 = ECNamedCurveTable.GetByName(CurveName);
        if (x9 == null) throw new CryptographicException($"无法加载曲线 {CurveName}。");
        return new ECDomainParameters(x9);
    }
}
