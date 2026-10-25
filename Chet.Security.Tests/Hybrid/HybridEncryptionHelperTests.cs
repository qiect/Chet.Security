using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Hybrid;

/// <summary>
/// 混合加密（信封加密）单元测试
/// </summary>
public class HybridEncryptionHelperTests
{
    private static readonly string RsaPublicKeyPem;
    private static readonly string RsaPrivateKeyPem;
    private static readonly string Sm2PublicKeyBase64;
    private static readonly string Sm2PrivateKeyBase64;
    private static readonly string EccPublicKeyPem;
    private static readonly string EccPrivateKeyPem;

    static HybridEncryptionHelperTests()
    {
        (RsaPublicKeyPem, RsaPrivateKeyPem) = RSAHelper.GenerateKeyPair();
        (Sm2PublicKeyBase64, Sm2PrivateKeyBase64) = SM2Helper.GenerateKeyPair();
        (EccPublicKeyPem, EccPrivateKeyPem) = ECCHelper.GenerateKeyPair();
    }

    #region RSA + AES-256-GCM

    /// <summary>
    /// 验证 RSA + AES-256-GCM 混合加密解密往返一致性
    /// </summary>
    [Fact]
    public void RsaAesGcm_EncryptDecrypt_RoundTrips()
    {
        var plain = "RSA+AES-GCM 混合加密测试 123";
        var envelope = HybridEncryptionHelper.RsaAesGcmEncrypt(plain, RsaPublicKeyPem);
        var decrypted = HybridEncryptionHelper.RsaAesGcmDecrypt(envelope, RsaPrivateKeyPem);
        Assert.Equal(plain, decrypted);
    }

    /// <summary>
    /// 验证 RSA + AES-256-GCM 混合加密对 Unicode 字符（含 emoji）的往返一致性
    /// </summary>
    [Fact]
    public void RsaAesGcm_EncryptDecrypt_Unicode_RoundTrips()
    {
        var plain = "混合加密 Unicode 测试 🔒🔑🛡️";
        var envelope = HybridEncryptionHelper.RsaAesGcmEncrypt(plain, RsaPublicKeyPem);
        var decrypted = HybridEncryptionHelper.RsaAesGcmDecrypt(envelope, RsaPrivateKeyPem);
        Assert.Equal(plain, decrypted);
    }

    /// <summary>
    /// 验证 RSA + AES-256-GCM 混合加密对长文本的往返一致性
    /// </summary>
    [Fact]
    public void RsaAesGcm_EncryptDecrypt_LongText_RoundTrips()
    {
        var plain = new string('X', 10000) + "尾部测试";
        var envelope = HybridEncryptionHelper.RsaAesGcmEncrypt(plain, RsaPublicKeyPem);
        var decrypted = HybridEncryptionHelper.RsaAesGcmDecrypt(envelope, RsaPrivateKeyPem);
        Assert.Equal(plain, decrypted);
    }

    /// <summary>
    /// 验证 RSA + AES-256-GCM 信封格式为点分隔的三段 Base64
    /// </summary>
    [Fact]
    public void RsaAesGcm_EnvelopeFormat_ThreeDotSeparatedParts()
    {
        var envelope = HybridEncryptionHelper.RsaAesGcmEncrypt("test", RsaPublicKeyPem);
        var parts = envelope.Split('.');
        Assert.Equal(3, parts.Length);
    }

    /// <summary>
    /// 验证 RSA + AES-256-GCM 每次加密产生不同的信封（随机会话密钥 + 随机 nonce）
    /// </summary>
    [Fact]
    public void RsaAesGcm_DifferentEncryptionsProduceDifferentEnvelopes()
    {
        var plain = "确定性测试";
        var envelope1 = HybridEncryptionHelper.RsaAesGcmEncrypt(plain, RsaPublicKeyPem);
        var envelope2 = HybridEncryptionHelper.RsaAesGcmEncrypt(plain, RsaPublicKeyPem);
        Assert.NotEqual(envelope1, envelope2);
    }

    #endregion

    #region RSA + AES-256-CBC

    /// <summary>
    /// 验证 RSA + AES-256-CBC 混合加密解密往返一致性
    /// </summary>
    [Fact]
    public void RsaAesCbc_EncryptDecrypt_RoundTrips()
    {
        var plain = "RSA+AES-CBC 混合加密测试 456";
        var envelope = HybridEncryptionHelper.RsaAesCbcEncrypt(plain, RsaPublicKeyPem);
        var decrypted = HybridEncryptionHelper.RsaAesCbcDecrypt(envelope, RsaPrivateKeyPem);
        Assert.Equal(plain, decrypted);
    }

    /// <summary>
    /// 验证 RSA + AES-256-CBC 混合加密对长文本的往返一致性
    /// </summary>
    [Fact]
    public void RsaAesCbc_EncryptDecrypt_LongText_RoundTrips()
    {
        var plain = new string('Y', 10000) + "CBC尾部";
        var envelope = HybridEncryptionHelper.RsaAesCbcEncrypt(plain, RsaPublicKeyPem);
        var decrypted = HybridEncryptionHelper.RsaAesCbcDecrypt(envelope, RsaPrivateKeyPem);
        Assert.Equal(plain, decrypted);
    }

    /// <summary>
    /// 验证 RSA + AES-256-CBC 信封格式为点分隔的三段 Base64
    /// </summary>
    [Fact]
    public void RsaAesCbc_EnvelopeFormat_ThreeDotSeparatedParts()
    {
        var envelope = HybridEncryptionHelper.RsaAesCbcEncrypt("test", RsaPublicKeyPem);
        var parts = envelope.Split('.');
        Assert.Equal(3, parts.Length);
    }

    #endregion

    #region RSA + ChaCha20-Poly1305

    /// <summary>
    /// 验证 RSA + ChaCha20-Poly1305 混合加密解密往返一致性
    /// </summary>
    [Fact]
    public void RsaChaCha20_EncryptDecrypt_RoundTrips()
    {
        var plain = "RSA+ChaCha20 混合加密测试 789";
        var envelope = HybridEncryptionHelper.RsaChaCha20Encrypt(plain, RsaPublicKeyPem);
        var decrypted = HybridEncryptionHelper.RsaChaCha20Decrypt(envelope, RsaPrivateKeyPem);
        Assert.Equal(plain, decrypted);
    }

    /// <summary>
    /// 验证 RSA + ChaCha20-Poly1305 混合加密对 Unicode 字符的往返一致性
    /// </summary>
    [Fact]
    public void RsaChaCha20_EncryptDecrypt_Unicode_RoundTrips()
    {
        var plain = "ChaCha20 Unicode 🔒🔑";
        var envelope = HybridEncryptionHelper.RsaChaCha20Encrypt(plain, RsaPublicKeyPem);
        var decrypted = HybridEncryptionHelper.RsaChaCha20Decrypt(envelope, RsaPrivateKeyPem);
        Assert.Equal(plain, decrypted);
    }

    /// <summary>
    /// 验证 RSA + ChaCha20-Poly1305 混合加密对长文本的往返一致性
    /// </summary>
    [Fact]
    public void RsaChaCha20_EncryptDecrypt_LongText_RoundTrips()
    {
        var plain = new string('Z', 10000) + "ChaCha20尾部";
        var envelope = HybridEncryptionHelper.RsaChaCha20Encrypt(plain, RsaPublicKeyPem);
        var decrypted = HybridEncryptionHelper.RsaChaCha20Decrypt(envelope, RsaPrivateKeyPem);
        Assert.Equal(plain, decrypted);
    }

    /// <summary>
    /// 验证 RSA + ChaCha20-Poly1305 信封格式为点分隔的三段 Base64
    /// </summary>
    [Fact]
    public void RsaChaCha20_EnvelopeFormat_ThreeDotSeparatedParts()
    {
        var envelope = HybridEncryptionHelper.RsaChaCha20Encrypt("test", RsaPublicKeyPem);
        var parts = envelope.Split('.');
        Assert.Equal(3, parts.Length);
    }

    #endregion

    #region SM2 + AES-256-GCM

    /// <summary>
    /// 验证 SM2 + AES-256-GCM 混合加密解密往返一致性
    /// </summary>
    [Fact]
    public void Sm2AesGcm_EncryptDecrypt_RoundTrips()
    {
        var plain = "SM2+AES-GCM 混合加密测试 abc";
        var envelope = HybridEncryptionHelper.Sm2AesGcmEncrypt(plain, Sm2PublicKeyBase64);
        var decrypted = HybridEncryptionHelper.Sm2AesGcmDecrypt(envelope, Sm2PrivateKeyBase64);
        Assert.Equal(plain, decrypted);
    }

    /// <summary>
    /// 验证 SM2 + AES-256-GCM 混合加密对 Unicode 字符的往返一致性
    /// </summary>
    [Fact]
    public void Sm2AesGcm_EncryptDecrypt_Unicode_RoundTrips()
    {
        var plain = "国密混合加密 🔒🇨🇳";
        var envelope = HybridEncryptionHelper.Sm2AesGcmEncrypt(plain, Sm2PublicKeyBase64);
        var decrypted = HybridEncryptionHelper.Sm2AesGcmDecrypt(envelope, Sm2PrivateKeyBase64);
        Assert.Equal(plain, decrypted);
    }

    /// <summary>
    /// 验证 SM2 + AES-256-GCM 混合加密对长文本的往返一致性
    /// </summary>
    [Fact]
    public void Sm2AesGcm_EncryptDecrypt_LongText_RoundTrips()
    {
        var plain = new string('S', 10000) + "SM2尾部";
        var envelope = HybridEncryptionHelper.Sm2AesGcmEncrypt(plain, Sm2PublicKeyBase64);
        var decrypted = HybridEncryptionHelper.Sm2AesGcmDecrypt(envelope, Sm2PrivateKeyBase64);
        Assert.Equal(plain, decrypted);
    }

    /// <summary>
    /// 验证 SM2 + AES-256-GCM 信封格式为点分隔的三段 Base64
    /// </summary>
    [Fact]
    public void Sm2AesGcm_EnvelopeFormat_ThreeDotSeparatedParts()
    {
        var envelope = HybridEncryptionHelper.Sm2AesGcmEncrypt("test", Sm2PublicKeyBase64);
        var parts = envelope.Split('.');
        Assert.Equal(3, parts.Length);
    }

    #endregion

    #region SM2 + SM4-CBC

    /// <summary>
    /// 验证 SM2 + SM4-CBC 混合加密解密往返一致性（纯国密方案）
    /// </summary>
    [Fact]
    public void Sm2Sm4_EncryptDecrypt_RoundTrips()
    {
        var plain = "SM2+SM4 纯国密混合加密测试 国密";
        var envelope = HybridEncryptionHelper.Sm2Sm4Encrypt(plain, Sm2PublicKeyBase64);
        var decrypted = HybridEncryptionHelper.Sm2Sm4Decrypt(envelope, Sm2PrivateKeyBase64);
        Assert.Equal(plain, decrypted);
    }

    /// <summary>
    /// 验证 SM2 + SM4-CBC 混合加密对长文本的往返一致性
    /// </summary>
    [Fact]
    public void Sm2Sm4_EncryptDecrypt_LongText_RoundTrips()
    {
        var plain = new string('M', 10000) + "SM4尾部";
        var envelope = HybridEncryptionHelper.Sm2Sm4Encrypt(plain, Sm2PublicKeyBase64);
        var decrypted = HybridEncryptionHelper.Sm2Sm4Decrypt(envelope, Sm2PrivateKeyBase64);
        Assert.Equal(plain, decrypted);
    }

    /// <summary>
    /// 验证 SM2 + SM4-CBC 信封格式为点分隔的三段 Base64
    /// </summary>
    [Fact]
    public void Sm2Sm4_EnvelopeFormat_ThreeDotSeparatedParts()
    {
        var envelope = HybridEncryptionHelper.Sm2Sm4Encrypt("test", Sm2PublicKeyBase64);
        var parts = envelope.Split('.');
        Assert.Equal(3, parts.Length);
    }

    #endregion

    #region SM2 + ChaCha20-Poly1305

    /// <summary>
    /// 验证 SM2 + ChaCha20-Poly1305 混合加密解密往返一致性
    /// </summary>
    [Fact]
    public void Sm2ChaCha20_EncryptDecrypt_RoundTrips()
    {
        var plain = "SM2+ChaCha20 混合加密测试 xyz";
        var envelope = HybridEncryptionHelper.Sm2ChaCha20Encrypt(plain, Sm2PublicKeyBase64);
        var decrypted = HybridEncryptionHelper.Sm2ChaCha20Decrypt(envelope, Sm2PrivateKeyBase64);
        Assert.Equal(plain, decrypted);
    }

    /// <summary>
    /// 验证 SM2 + ChaCha20-Poly1305 混合加密对长文本的往返一致性
    /// </summary>
    [Fact]
    public void Sm2ChaCha20_EncryptDecrypt_LongText_RoundTrips()
    {
        var plain = new string('C', 10000) + "ChaCha尾部";
        var envelope = HybridEncryptionHelper.Sm2ChaCha20Encrypt(plain, Sm2PublicKeyBase64);
        var decrypted = HybridEncryptionHelper.Sm2ChaCha20Decrypt(envelope, Sm2PrivateKeyBase64);
        Assert.Equal(plain, decrypted);
    }

    /// <summary>
    /// 验证 SM2 + ChaCha20-Poly1305 信封格式为点分隔的三段 Base64
    /// </summary>
    [Fact]
    public void Sm2ChaCha20_EnvelopeFormat_ThreeDotSeparatedParts()
    {
        var envelope = HybridEncryptionHelper.Sm2ChaCha20Encrypt("test", Sm2PublicKeyBase64);
        var parts = envelope.Split('.');
        Assert.Equal(3, parts.Length);
    }

    #endregion

    #region ECIES (ECDH + AES-256-GCM)

    /// <summary>
    /// 验证 ECIES（ECDH + AES-256-GCM）混合加密解密往返一致性
    /// </summary>
    [Fact]
    public void Ecies_EncryptDecrypt_RoundTrips()
    {
        var plain = "ECIES 混合加密测试 ecdh";
        var envelope = HybridEncryptionHelper.EciesEncrypt(plain, EccPublicKeyPem);
        var decrypted = HybridEncryptionHelper.EciesDecrypt(envelope, EccPrivateKeyPem);
        Assert.Equal(plain, decrypted);
    }

    /// <summary>
    /// 验证 ECIES 混合加密对 Unicode 字符的往返一致性
    /// </summary>
    [Fact]
    public void Ecies_EncryptDecrypt_Unicode_RoundTrips()
    {
        var plain = "ECIES Unicode 🔒🔑🛡️";
        var envelope = HybridEncryptionHelper.EciesEncrypt(plain, EccPublicKeyPem);
        var decrypted = HybridEncryptionHelper.EciesDecrypt(envelope, EccPrivateKeyPem);
        Assert.Equal(plain, decrypted);
    }

    /// <summary>
    /// 验证 ECIES 混合加密对长文本的往返一致性
    /// </summary>
    [Fact]
    public void Ecies_EncryptDecrypt_LongText_RoundTrips()
    {
        var plain = new string('E', 10000) + "ECIES尾部";
        var envelope = HybridEncryptionHelper.EciesEncrypt(plain, EccPublicKeyPem);
        var decrypted = HybridEncryptionHelper.EciesDecrypt(envelope, EccPrivateKeyPem);
        Assert.Equal(plain, decrypted);
    }

    /// <summary>
    /// 验证 ECIES 信封格式为点分隔的三段 Base64
    /// </summary>
    [Fact]
    public void Ecies_EnvelopeFormat_ThreeDotSeparatedParts()
    {
        var envelope = HybridEncryptionHelper.EciesEncrypt("test", EccPublicKeyPem);
        var parts = envelope.Split('.');
        Assert.Equal(3, parts.Length);
    }

    /// <summary>
    /// 验证 ECIES 每次加密产生不同的信封（临时密钥对提供前向安全性）
    /// </summary>
    [Fact]
    public void Ecies_DifferentEncryptionsProduceDifferentEnvelopes()
    {
        var plain = "前向安全性测试";
        var envelope1 = HybridEncryptionHelper.EciesEncrypt(plain, EccPublicKeyPem);
        var envelope2 = HybridEncryptionHelper.EciesEncrypt(plain, EccPublicKeyPem);
        Assert.NotEqual(envelope1, envelope2);
    }

    #endregion

    #region ECIES (ECDH + ChaCha20-Poly1305)

    /// <summary>
    /// 验证 ECIES + ChaCha20-Poly1305 混合加密解密往返一致性
    /// </summary>
    [Fact]
    public void EciesChaCha20_EncryptDecrypt_RoundTrips()
    {
        var plain = "ECIES+ChaCha20 混合加密测试";
        var envelope = HybridEncryptionHelper.EciesChaCha20Encrypt(plain, EccPublicKeyPem);
        var decrypted = HybridEncryptionHelper.EciesChaCha20Decrypt(envelope, EccPrivateKeyPem);
        Assert.Equal(plain, decrypted);
    }

    /// <summary>
    /// 验证 ECIES + ChaCha20-Poly1305 混合加密对长文本的往返一致性
    /// </summary>
    [Fact]
    public void EciesChaCha20_EncryptDecrypt_LongText_RoundTrips()
    {
        var plain = new string('H', 10000) + "ECIES-ChaCha20尾部";
        var envelope = HybridEncryptionHelper.EciesChaCha20Encrypt(plain, EccPublicKeyPem);
        var decrypted = HybridEncryptionHelper.EciesChaCha20Decrypt(envelope, EccPrivateKeyPem);
        Assert.Equal(plain, decrypted);
    }

    /// <summary>
    /// 验证 ECIES + ChaCha20-Poly1305 信封格式为点分隔的三段 Base64
    /// </summary>
    [Fact]
    public void EciesChaCha20_EnvelopeFormat_ThreeDotSeparatedParts()
    {
        var envelope = HybridEncryptionHelper.EciesChaCha20Encrypt("test", EccPublicKeyPem);
        var parts = envelope.Split('.');
        Assert.Equal(3, parts.Length);
    }

    /// <summary>
    /// 验证 ECIES + ChaCha20-Poly1305 每次加密产生不同的信封
    /// </summary>
    [Fact]
    public void EciesChaCha20_DifferentEncryptionsProduceDifferentEnvelopes()
    {
        var plain = "前向安全性测试 ChaCha20";
        var envelope1 = HybridEncryptionHelper.EciesChaCha20Encrypt(plain, EccPublicKeyPem);
        var envelope2 = HybridEncryptionHelper.EciesChaCha20Encrypt(plain, EccPublicKeyPem);
        Assert.NotEqual(envelope1, envelope2);
    }

    #endregion

    #region 异常与边界情况

    /// <summary>
    /// 验证空明文加密时抛出异常
    /// </summary>
    [Fact]
    public void RsaAesGcm_NullPlain_Throws()
    {
        Assert.ThrowsAny<Exception>(() => HybridEncryptionHelper.RsaAesGcmEncrypt(null!, RsaPublicKeyPem));
    }

    /// <summary>
    /// 验证空公钥加密时抛出异常
    /// </summary>
    [Fact]
    public void RsaAesGcm_NullPublicKey_Throws()
    {
        Assert.ThrowsAny<Exception>(() => HybridEncryptionHelper.RsaAesGcmEncrypt("test", null!));
    }

    /// <summary>
    /// 验证格式无效的信封解密时抛出异常
    /// </summary>
    [Fact]
    public void RsaAesGcm_InvalidEnvelopeFormat_Throws()
    {
        Assert.ThrowsAny<Exception>(() => HybridEncryptionHelper.RsaAesGcmDecrypt("invalid-no-dots", RsaPrivateKeyPem));
    }

    /// <summary>
    /// 验证段数不正确的信封解密时抛出异常
    /// </summary>
    [Fact]
    public void RsaAesGcm_WrongPartCount_Throws()
    {
        Assert.ThrowsAny<Exception>(() => HybridEncryptionHelper.RsaAesGcmDecrypt("a.b", RsaPrivateKeyPem));
    }

    /// <summary>
    /// 验证空信封解密时抛出异常
    /// </summary>
    [Fact]
    public void RsaAesGcm_NullEnvelope_Throws()
    {
        Assert.ThrowsAny<Exception>(() => HybridEncryptionHelper.RsaAesGcmDecrypt(null!, RsaPrivateKeyPem));
    }

    /// <summary>
    /// 验证 SM2 + AES-256-GCM 空明文加密时抛出异常
    /// </summary>
    [Fact]
    public void Sm2AesGcm_NullPlain_Throws()
    {
        Assert.ThrowsAny<Exception>(() => HybridEncryptionHelper.Sm2AesGcmEncrypt(null!, Sm2PublicKeyBase64));
    }

    /// <summary>
    /// 验证 ECIES 空明文加密时抛出异常
    /// </summary>
    [Fact]
    public void Ecies_NullPlain_Throws()
    {
        Assert.ThrowsAny<Exception>(() => HybridEncryptionHelper.EciesEncrypt(null!, EccPublicKeyPem));
    }

    #endregion

    #region 跨方案互操作性验证

    /// <summary>
    /// 验证同一明文经不同 RSA 混合加密方案加密后均可正确解密（互不干扰）
    /// </summary>
    [Fact]
    public void RsaSchemes_SamePlaintext_AllDecryptCorrectly()
    {
        var plain = "跨方案互操作性验证数据";

        var gcmEnvelope = HybridEncryptionHelper.RsaAesGcmEncrypt(plain, RsaPublicKeyPem);
        var cbcEnvelope = HybridEncryptionHelper.RsaAesCbcEncrypt(plain, RsaPublicKeyPem);
        var chachaEnvelope = HybridEncryptionHelper.RsaChaCha20Encrypt(plain, RsaPublicKeyPem);

        Assert.Equal(plain, HybridEncryptionHelper.RsaAesGcmDecrypt(gcmEnvelope, RsaPrivateKeyPem));
        Assert.Equal(plain, HybridEncryptionHelper.RsaAesCbcDecrypt(cbcEnvelope, RsaPrivateKeyPem));
        Assert.Equal(plain, HybridEncryptionHelper.RsaChaCha20Decrypt(chachaEnvelope, RsaPrivateKeyPem));

        Assert.NotEqual(gcmEnvelope, cbcEnvelope);
        Assert.NotEqual(gcmEnvelope, chachaEnvelope);
        Assert.NotEqual(cbcEnvelope, chachaEnvelope);
    }

    /// <summary>
    /// 验证同一明文经不同 SM2 混合加密方案加密后均可正确解密（互不干扰）
    /// </summary>
    [Fact]
    public void Sm2Schemes_SamePlaintext_AllDecryptCorrectly()
    {
        var plain = "国密跨方案互操作性验证";

        var gcmEnvelope = HybridEncryptionHelper.Sm2AesGcmEncrypt(plain, Sm2PublicKeyBase64);
        var sm4Envelope = HybridEncryptionHelper.Sm2Sm4Encrypt(plain, Sm2PublicKeyBase64);
        var chachaEnvelope = HybridEncryptionHelper.Sm2ChaCha20Encrypt(plain, Sm2PublicKeyBase64);

        Assert.Equal(plain, HybridEncryptionHelper.Sm2AesGcmDecrypt(gcmEnvelope, Sm2PrivateKeyBase64));
        Assert.Equal(plain, HybridEncryptionHelper.Sm2Sm4Decrypt(sm4Envelope, Sm2PrivateKeyBase64));
        Assert.Equal(plain, HybridEncryptionHelper.Sm2ChaCha20Decrypt(chachaEnvelope, Sm2PrivateKeyBase64));
    }

    /// <summary>
    /// 验证同一明文经不同 ECIES 混合加密方案加密后均可正确解密（互不干扰）
    /// </summary>
    [Fact]
    public void EciesSchemes_SamePlaintext_AllDecryptCorrectly()
    {
        var plain = "ECIES跨方案互操作性验证";

        var aesEnvelope = HybridEncryptionHelper.EciesEncrypt(plain, EccPublicKeyPem);
        var chachaEnvelope = HybridEncryptionHelper.EciesChaCha20Encrypt(plain, EccPublicKeyPem);

        Assert.Equal(plain, HybridEncryptionHelper.EciesDecrypt(aesEnvelope, EccPrivateKeyPem));
        Assert.Equal(plain, HybridEncryptionHelper.EciesChaCha20Decrypt(chachaEnvelope, EccPrivateKeyPem));
    }

    #endregion
}