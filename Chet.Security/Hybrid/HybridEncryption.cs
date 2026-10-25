namespace Chet.Security;

/// <summary>
/// 混合加密（信封加密 / Envelope Encryption / KEM+DEM）工具类。
/// </summary>
/// <remarks>
/// <para>
/// 混合加密用非对称算法（RSA / SM2 / ECDH）加密一个随机会话密钥（KEM 步骤），
/// 再用对称算法（AES-GCM / ChaCha20-Poly1305 / SM4-CBC / AES-CBC）加密实际数据（DEM 步骤），
/// 兼顾非对称的安全性与对称的性能。
/// </para>
/// <para>
/// 这是 TLS、PGP/GPG、S/MIME、JWE、CMS 等主流协议的标准做法，
/// 相比分段 RSA 加密性能提升 3~4 个数量级（1MB 数据：混合加密 ~2ms vs 分段 RSA ~5.5s）。
/// </para>
/// <para><b>信封格式</b>（点分隔的 Base64）：</para>
/// <list type="bullet">
/// <item>RSA/SM2 系列：<c>encryptedSessionKey.nonceOrIV.ciphertextData</c></item>
/// <item>ECIES 系列：<c>ephemeralPublicKey.nonce.ciphertextData</c>（第一段为临时公钥而非加密密钥）</item>
/// </list>
/// <para>
/// AEAD 模式（AES-GCM / ChaCha20-Poly1305）的 ciphertextData 包含密文与 16 字节认证 Tag；
/// CBC 模式（SM4-CBC / AES-CBC）的 ciphertextData 仅含密文（无认证 Tag，建议优先使用 AEAD 模式）。
/// </para>
/// </remarks>
public static class HybridEncryptionHelper
{
    private const string EnvelopeSeparator = ".";

    #region RSA + AES-256-GCM

    /// <summary>RSA + AES-256-GCM 混合加密：RSA-OAEP-SHA256 加密随机 AES 会话密钥，AES-256-GCM 加密数据。推荐作为默认长文本加密方案。</summary>
    /// <param name="plain">待加密明文。</param>
    /// <param name="rsaPublicKeyPem">RSA 公钥 PEM（SubjectPublicKeyInfo 格式）。</param>
    /// <returns>信封字符串，格式为 <c>encryptedKey.nonce.ciphertextWithTag</c>（点分隔的 Base64）。</returns>
    public static string RsaAesGcmEncrypt(string plain, string rsaPublicKeyPem)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(plain, nameof(plain));
        CryptoPolyfill.ThrowIfNullOrEmpty(rsaPublicKeyPem, nameof(rsaPublicKeyPem));

        byte[] aesKey = SecureRandomHelper.GenerateBytes(32);
        byte[] nonce = SecureRandomHelper.GenerateBytes(12);
        byte[] plainBytes = Encoding.UTF8.GetBytes(plain);
        byte[] cipherData = AESHelper.EncryptGCM(plainBytes, aesKey, nonce);
        string encryptedKey = RSAHelper.Encrypt(Convert.ToBase64String(aesKey), rsaPublicKeyPem);

        return string.Join(EnvelopeSeparator,
            encryptedKey,
            Convert.ToBase64String(nonce),
            Convert.ToBase64String(cipherData));
    }

    /// <summary>RSA + AES-256-GCM 混合解密。</summary>
    /// <param name="envelope">信封字符串。</param>
    /// <param name="rsaPrivateKeyPem">RSA 私钥 PEM（PKCS#8 格式）。</param>
    /// <returns>明文。</returns>
    public static string RsaAesGcmDecrypt(string envelope, string rsaPrivateKeyPem)
    {
        var parts = ParseEnvelope(envelope, 3);
        byte[] aesKey = Convert.FromBase64String(RSAHelper.Decrypt(parts[0], rsaPrivateKeyPem));
        byte[] nonce = Convert.FromBase64String(parts[1]);
        byte[] cipherData = Convert.FromBase64String(parts[2]);
        byte[] plainBytes = AESHelper.DecryptGCM(cipherData, aesKey, nonce);
        return Encoding.UTF8.GetString(plainBytes);
    }

    #endregion

    #region RSA + AES-256-CBC

    /// <summary>RSA + AES-256-CBC 混合加密：RSA-OAEP-SHA256 加密随机 AES 会话密钥，AES-256-CBC 加密数据。</summary>
    /// <param name="plain">待加密明文。</param>
    /// <param name="rsaPublicKeyPem">RSA 公钥 PEM。</param>
    /// <returns>信封字符串，格式为 <c>encryptedKey.iv.ciphertext</c>（点分隔的 Base64）。</returns>
    /// <remarks>CBC 模式不提供认证保护（无 MAC/Tag），建议优先使用 <see cref="RsaAesGcmEncrypt"/>。</remarks>
    public static string RsaAesCbcEncrypt(string plain, string rsaPublicKeyPem)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(plain, nameof(plain));
        CryptoPolyfill.ThrowIfNullOrEmpty(rsaPublicKeyPem, nameof(rsaPublicKeyPem));

        byte[] aesKey = SecureRandomHelper.GenerateBytes(32);
        byte[] iv = SecureRandomHelper.GenerateBytes(16);
        byte[] plainBytes = Encoding.UTF8.GetBytes(plain);
        byte[] cipherData = AESHelper.Encrypt(plainBytes, aesKey, iv, CipherMode.CBC);
        string encryptedKey = RSAHelper.Encrypt(Convert.ToBase64String(aesKey), rsaPublicKeyPem);

        return string.Join(EnvelopeSeparator,
            encryptedKey,
            Convert.ToBase64String(iv),
            Convert.ToBase64String(cipherData));
    }

    /// <summary>RSA + AES-256-CBC 混合解密。</summary>
    /// <param name="envelope">信封字符串。</param>
    /// <param name="rsaPrivateKeyPem">RSA 私钥 PEM。</param>
    /// <returns>明文。</returns>
    public static string RsaAesCbcDecrypt(string envelope, string rsaPrivateKeyPem)
    {
        var parts = ParseEnvelope(envelope, 3);
        byte[] aesKey = Convert.FromBase64String(RSAHelper.Decrypt(parts[0], rsaPrivateKeyPem));
        byte[] iv = Convert.FromBase64String(parts[1]);
        byte[] cipherData = Convert.FromBase64String(parts[2]);
        byte[] plainBytes = AESHelper.Decrypt(cipherData, aesKey, iv, CipherMode.CBC);
        return Encoding.UTF8.GetString(plainBytes);
    }

    #endregion

    #region RSA + ChaCha20-Poly1305

    /// <summary>RSA + ChaCha20-Poly1305 混合加密：RSA-OAEP-SHA256 加密随机 ChaCha20 会话密钥，ChaCha20-Poly1305 加密数据。</summary>
    /// <param name="plain">待加密明文。</param>
    /// <param name="rsaPublicKeyPem">RSA 公钥 PEM。</param>
    /// <returns>信封字符串，格式为 <c>encryptedKey.nonce.ciphertextWithTag</c>（点分隔的 Base64）。</returns>
    public static string RsaChaCha20Encrypt(string plain, string rsaPublicKeyPem)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(plain, nameof(plain));
        CryptoPolyfill.ThrowIfNullOrEmpty(rsaPublicKeyPem, nameof(rsaPublicKeyPem));

        byte[] key = SecureRandomHelper.GenerateBytes(32);
        byte[] nonce = SecureRandomHelper.GenerateBytes(12);
        byte[] plainBytes = Encoding.UTF8.GetBytes(plain);
        byte[] cipherData = ChaCha20Poly1305Helper.Encrypt(plainBytes, key, nonce);
        string encryptedKey = RSAHelper.Encrypt(Convert.ToBase64String(key), rsaPublicKeyPem);

        return string.Join(EnvelopeSeparator,
            encryptedKey,
            Convert.ToBase64String(nonce),
            Convert.ToBase64String(cipherData));
    }

    /// <summary>RSA + ChaCha20-Poly1305 混合解密。</summary>
    /// <param name="envelope">信封字符串。</param>
    /// <param name="rsaPrivateKeyPem">RSA 私钥 PEM。</param>
    /// <returns>明文。</returns>
    public static string RsaChaCha20Decrypt(string envelope, string rsaPrivateKeyPem)
    {
        var parts = ParseEnvelope(envelope, 3);
        byte[] key = Convert.FromBase64String(RSAHelper.Decrypt(parts[0], rsaPrivateKeyPem));
        byte[] nonce = Convert.FromBase64String(parts[1]);
        byte[] cipherData = Convert.FromBase64String(parts[2]);
        byte[] plainBytes = ChaCha20Poly1305Helper.Decrypt(cipherData, key, nonce);
        return Encoding.UTF8.GetString(plainBytes);
    }

    #endregion

    #region SM2 + AES-256-GCM

    /// <summary>SM2 + AES-256-GCM 混合加密：SM2 加密随机 AES 会话密钥，AES-256-GCM 加密数据。国密公钥 + 国际对称算法组合。</summary>
    /// <param name="plain">待加密明文。</param>
    /// <param name="sm2PublicKeyBase64">SM2 公钥 Base64（未压缩点，65 字节）。</param>
    /// <returns>信封字符串，格式为 <c>encryptedKey.nonce.ciphertextWithTag</c>（点分隔的 Base64）。</returns>
    public static string Sm2AesGcmEncrypt(string plain, string sm2PublicKeyBase64)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(plain, nameof(plain));
        CryptoPolyfill.ThrowIfNullOrEmpty(sm2PublicKeyBase64, nameof(sm2PublicKeyBase64));

        byte[] aesKey = SecureRandomHelper.GenerateBytes(32);
        byte[] nonce = SecureRandomHelper.GenerateBytes(12);
        byte[] plainBytes = Encoding.UTF8.GetBytes(plain);
        byte[] cipherData = AESHelper.EncryptGCM(plainBytes, aesKey, nonce);
        string encryptedKey = SM2Helper.Encrypt(Convert.ToBase64String(aesKey), sm2PublicKeyBase64);

        return string.Join(EnvelopeSeparator,
            encryptedKey,
            Convert.ToBase64String(nonce),
            Convert.ToBase64String(cipherData));
    }

    /// <summary>SM2 + AES-256-GCM 混合解密。</summary>
    /// <param name="envelope">信封字符串。</param>
    /// <param name="sm2PrivateKeyBase64">SM2 私钥 Base64（32 字节标量）。</param>
    /// <returns>明文。</returns>
    public static string Sm2AesGcmDecrypt(string envelope, string sm2PrivateKeyBase64)
    {
        var parts = ParseEnvelope(envelope, 3);
        byte[] aesKey = Convert.FromBase64String(SM2Helper.Decrypt(parts[0], sm2PrivateKeyBase64));
        byte[] nonce = Convert.FromBase64String(parts[1]);
        byte[] cipherData = Convert.FromBase64String(parts[2]);
        byte[] plainBytes = AESHelper.DecryptGCM(cipherData, aesKey, nonce);
        return Encoding.UTF8.GetString(plainBytes);
    }

    #endregion

    #region SM2 + SM4-CBC

    /// <summary>SM2 + SM4-CBC 混合加密：SM2 加密随机 SM4 会话密钥，SM4-CBC 加密数据。纯国密混合加密方案。</summary>
    /// <param name="plain">待加密明文。</param>
    /// <param name="sm2PublicKeyBase64">SM2 公钥 Base64。</param>
    /// <returns>信封字符串，格式为 <c>encryptedKey.iv.ciphertext</c>（点分隔的 Base64）。</returns>
    /// <remarks>SM4-CBC 模式不提供认证保护，建议优先使用 <see cref="Sm2AesGcmEncrypt"/> 或 <see cref="Sm2ChaCha20Encrypt"/>。</remarks>
    public static string Sm2Sm4Encrypt(string plain, string sm2PublicKeyBase64)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(plain, nameof(plain));
        CryptoPolyfill.ThrowIfNullOrEmpty(sm2PublicKeyBase64, nameof(sm2PublicKeyBase64));

        byte[] sm4Key = SecureRandomHelper.GenerateBytes(16);
        byte[] iv = SecureRandomHelper.GenerateBytes(16);
        byte[] plainBytes = Encoding.UTF8.GetBytes(plain);
        byte[] cipherData = SM4Helper.Encrypt(plainBytes, sm4Key, iv);
        string encryptedKey = SM2Helper.Encrypt(Convert.ToBase64String(sm4Key), sm2PublicKeyBase64);

        return string.Join(EnvelopeSeparator,
            encryptedKey,
            Convert.ToBase64String(iv),
            Convert.ToBase64String(cipherData));
    }

    /// <summary>SM2 + SM4-CBC 混合解密。</summary>
    /// <param name="envelope">信封字符串。</param>
    /// <param name="sm2PrivateKeyBase64">SM2 私钥 Base64。</param>
    /// <returns>明文。</returns>
    public static string Sm2Sm4Decrypt(string envelope, string sm2PrivateKeyBase64)
    {
        var parts = ParseEnvelope(envelope, 3);
        byte[] sm4Key = Convert.FromBase64String(SM2Helper.Decrypt(parts[0], sm2PrivateKeyBase64));
        byte[] iv = Convert.FromBase64String(parts[1]);
        byte[] cipherData = Convert.FromBase64String(parts[2]);
        byte[] plainBytes = SM4Helper.Decrypt(cipherData, sm4Key, iv);
        return Encoding.UTF8.GetString(plainBytes);
    }

    #endregion

    #region SM2 + ChaCha20-Poly1305

    /// <summary>SM2 + ChaCha20-Poly1305 混合加密：SM2 加密随机 ChaCha20 会话密钥，ChaCha20-Poly1305 加密数据。国密公钥 + 现代 AEAD 对称算法组合。</summary>
    /// <param name="plain">待加密明文。</param>
    /// <param name="sm2PublicKeyBase64">SM2 公钥 Base64。</param>
    /// <returns>信封字符串，格式为 <c>encryptedKey.nonce.ciphertextWithTag</c>（点分隔的 Base64）。</returns>
    public static string Sm2ChaCha20Encrypt(string plain, string sm2PublicKeyBase64)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(plain, nameof(plain));
        CryptoPolyfill.ThrowIfNullOrEmpty(sm2PublicKeyBase64, nameof(sm2PublicKeyBase64));

        byte[] key = SecureRandomHelper.GenerateBytes(32);
        byte[] nonce = SecureRandomHelper.GenerateBytes(12);
        byte[] plainBytes = Encoding.UTF8.GetBytes(plain);
        byte[] cipherData = ChaCha20Poly1305Helper.Encrypt(plainBytes, key, nonce);
        string encryptedKey = SM2Helper.Encrypt(Convert.ToBase64String(key), sm2PublicKeyBase64);

        return string.Join(EnvelopeSeparator,
            encryptedKey,
            Convert.ToBase64String(nonce),
            Convert.ToBase64String(cipherData));
    }

    /// <summary>SM2 + ChaCha20-Poly1305 混合解密。</summary>
    /// <param name="envelope">信封字符串。</param>
    /// <param name="sm2PrivateKeyBase64">SM2 私钥 Base64。</param>
    /// <returns>明文。</returns>
    public static string Sm2ChaCha20Decrypt(string envelope, string sm2PrivateKeyBase64)
    {
        var parts = ParseEnvelope(envelope, 3);
        byte[] key = Convert.FromBase64String(SM2Helper.Decrypt(parts[0], sm2PrivateKeyBase64));
        byte[] nonce = Convert.FromBase64String(parts[1]);
        byte[] cipherData = Convert.FromBase64String(parts[2]);
        byte[] plainBytes = ChaCha20Poly1305Helper.Decrypt(cipherData, key, nonce);
        return Encoding.UTF8.GetString(plainBytes);
    }

    #endregion

    #region ECIES (ECDH + AES-256-GCM)

    /// <summary>
    /// ECIES（Elliptic Curve Integrated Encryption Scheme）混合加密：
    /// 生成临时 ECDH 密钥对，协商共享密钥，AES-256-GCM 加密数据。基于 NIST P-256 曲线。
    /// </summary>
    /// <param name="plain">待加密明文。</param>
    /// <param name="recipientPublicKeyPem">接收方 ECDH 公钥 PEM（SubjectPublicKeyInfo 格式，NIST P-256）。</param>
    /// <returns>信封字符串，格式为 <c>ephemeralPublicKey.nonce.ciphertextWithTag</c>（点分隔的 Base64），其中 ephemeralPublicKey 为临时公钥 PEM 的 Base64 编码。</returns>
    /// <remarks>
    /// ECIES 的安全性依赖于 ECDH 的 CDH 假设与 AES-GCM 的 AEAD 安全性。
    /// 每次加密生成新的临时密钥对，提供前向安全性（Forward Secrecy）。
    /// </remarks>
    public static string EciesEncrypt(string plain, string recipientPublicKeyPem)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(plain, nameof(plain));
        CryptoPolyfill.ThrowIfNullOrEmpty(recipientPublicKeyPem, nameof(recipientPublicKeyPem));

        var (ephemeralPublicPem, ephemeralPrivatePem) = ECCHelper.GenerateKeyPair();
        byte[] sharedSecret = ECCHelper.DeriveSharedSecret(ephemeralPrivatePem, recipientPublicKeyPem);
        byte[] nonce = SecureRandomHelper.GenerateBytes(12);
        byte[] plainBytes = Encoding.UTF8.GetBytes(plain);
        byte[] cipherData = AESHelper.EncryptGCM(plainBytes, sharedSecret, nonce);

        return string.Join(EnvelopeSeparator,
            Convert.ToBase64String(Encoding.UTF8.GetBytes(ephemeralPublicPem)),
            Convert.ToBase64String(nonce),
            Convert.ToBase64String(cipherData));
    }

    /// <summary>ECIES 混合解密：用接收方私钥与信封中的临时公钥协商共享密钥，AES-256-GCM 解密数据。</summary>
    /// <param name="envelope">信封字符串。</param>
    /// <param name="recipientPrivateKeyPem">接收方 ECDH 私钥 PEM（PKCS#8 格式）。</param>
    /// <returns>明文。</returns>
    public static string EciesDecrypt(string envelope, string recipientPrivateKeyPem)
    {
        var parts = ParseEnvelope(envelope, 3);
        string ephemeralPublicPem = Encoding.UTF8.GetString(Convert.FromBase64String(parts[0]));
        byte[] sharedSecret = ECCHelper.DeriveSharedSecret(recipientPrivateKeyPem, ephemeralPublicPem);
        byte[] nonce = Convert.FromBase64String(parts[1]);
        byte[] cipherData = Convert.FromBase64String(parts[2]);
        byte[] plainBytes = AESHelper.DecryptGCM(cipherData, sharedSecret, nonce);
        return Encoding.UTF8.GetString(plainBytes);
    }

    #endregion

    #region ECIES (ECDH + ChaCha20-Poly1305)

    /// <summary>
    /// ECIES + ChaCha20-Poly1305 混合加密：
    /// 生成临时 ECDH 密钥对，协商共享密钥，ChaCha20-Poly1305 加密数据。基于 NIST P-256 曲线。
    /// </summary>
    /// <param name="plain">待加密明文。</param>
    /// <param name="recipientPublicKeyPem">接收方 ECDH 公钥 PEM。</param>
    /// <returns>信封字符串，格式为 <c>ephemeralPublicKey.nonce.ciphertextWithTag</c>（点分隔的 Base64）。</returns>
    public static string EciesChaCha20Encrypt(string plain, string recipientPublicKeyPem)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(plain, nameof(plain));
        CryptoPolyfill.ThrowIfNullOrEmpty(recipientPublicKeyPem, nameof(recipientPublicKeyPem));

        var (ephemeralPublicPem, ephemeralPrivatePem) = ECCHelper.GenerateKeyPair();
        byte[] sharedSecret = ECCHelper.DeriveSharedSecret(ephemeralPrivatePem, recipientPublicKeyPem);
        byte[] nonce = SecureRandomHelper.GenerateBytes(12);
        byte[] plainBytes = Encoding.UTF8.GetBytes(plain);
        byte[] cipherData = ChaCha20Poly1305Helper.Encrypt(plainBytes, sharedSecret, nonce);

        return string.Join(EnvelopeSeparator,
            Convert.ToBase64String(Encoding.UTF8.GetBytes(ephemeralPublicPem)),
            Convert.ToBase64String(nonce),
            Convert.ToBase64String(cipherData));
    }

    /// <summary>ECIES + ChaCha20-Poly1305 混合解密。</summary>
    /// <param name="envelope">信封字符串。</param>
    /// <param name="recipientPrivateKeyPem">接收方 ECDH 私钥 PEM。</param>
    /// <returns>明文。</returns>
    public static string EciesChaCha20Decrypt(string envelope, string recipientPrivateKeyPem)
    {
        var parts = ParseEnvelope(envelope, 3);
        string ephemeralPublicPem = Encoding.UTF8.GetString(Convert.FromBase64String(parts[0]));
        byte[] sharedSecret = ECCHelper.DeriveSharedSecret(recipientPrivateKeyPem, ephemeralPublicPem);
        byte[] nonce = Convert.FromBase64String(parts[1]);
        byte[] cipherData = Convert.FromBase64String(parts[2]);
        byte[] plainBytes = ChaCha20Poly1305Helper.Decrypt(cipherData, sharedSecret, nonce);
        return Encoding.UTF8.GetString(plainBytes);
    }

    #endregion

    /// <summary>解析信封字符串，验证段数。</summary>
    private static string[] ParseEnvelope(string envelope, int expectedParts)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(envelope, nameof(envelope));
        var parts = envelope.Split(new[] { EnvelopeSeparator }, StringSplitOptions.None);
        if (parts.Length != expectedParts)
            throw new FormatException(
                $"信封格式无效：应为 {expectedParts} 个点分隔的 Base64 部分，实际为 {parts.Length} 个。");
        return parts;
    }
}