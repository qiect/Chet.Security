namespace Chet.Security;

/// <summary>
/// TripleDES（3DES）对称加密工具类，使用 CBC 模式与 PKCS7 填充。
/// </summary>
/// <remarks>
/// 3DES 有效强度约 112 位，虽强于 DES 但已不推荐用于新系统，建议优先使用 <see cref="AESHelper"/>。
/// </remarks>
public static class TripleDESHelper
{
    /// <summary>使用 CBC + PKCS7 加密 UTF-8 明文，返回 Base64 密文。密钥规范化为 192 位，IV 由 <paramref name="key"/> 规范化为 64 位。</summary>
    /// <param name="plain">明文字符串。</param>
    /// <param name="key">密钥（任意长度，将规范化为 192 位；同时用作 IV 来源）。</param>
    /// <returns>Base64 编码的密文。</returns>
    public static string Encrypt(string plain, string key)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(plain, nameof(plain));
        CryptoPolyfill.ThrowIfNullOrEmpty(key, nameof(key));
        var keyBytes = SecurityHelper.NormalizeKey(key, KeyNormalizeMode.Hash, 192);
        var ivBytes = SecurityHelper.NormalizeKey(key, KeyNormalizeMode.Hash, 64);
        var cipher = Encrypt(Encoding.UTF8.GetBytes(plain), keyBytes, ivBytes);
        return Convert.ToBase64String(cipher);
    }

    /// <summary>解密 Base64 密文为 UTF-8 明文。密钥规范化为 192 位，IV 由 <paramref name="key"/> 规范化为 64 位。</summary>
    /// <param name="cipherBase64">Base64 编码的密文。</param>
    /// <param name="key">密钥（任意长度，将规范化为 192 位；同时用作 IV 来源）。</param>
    /// <returns>UTF-8 明文字符串。</returns>
    public static string Decrypt(string cipherBase64, string key)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(cipherBase64, nameof(cipherBase64));
        CryptoPolyfill.ThrowIfNullOrEmpty(key, nameof(key));
        var keyBytes = SecurityHelper.NormalizeKey(key, KeyNormalizeMode.Hash, 192);
        var ivBytes = SecurityHelper.NormalizeKey(key, KeyNormalizeMode.Hash, 64);
        var plain = Decrypt(Convert.FromBase64String(cipherBase64), keyBytes, ivBytes);
        return Encoding.UTF8.GetString(plain);
    }

    /// <summary>使用 CBC + PKCS7 加密字节数组。要求 key 为 16/24 字节，iv 为 8 字节。</summary>
    /// <param name="plain">明文字节数组。</param>
    /// <param name="key">16 或 24 字节密钥。</param>
    /// <param name="iv">8 字节 IV。</param>
    /// <returns>密文字节数组。</returns>
    public static byte[] Encrypt(byte[] plain, byte[] key, byte[] iv)
    {
        if (plain is null) throw new ArgumentNullException(nameof(plain));
        if (key is null) throw new ArgumentNullException(nameof(key));
        if (iv is null) throw new ArgumentNullException(nameof(iv));
        return Transform(plain, key, iv, encrypt: true);
    }

    /// <summary>使用 CBC + PKCS7 解密字节数组。要求 key 为 16/24 字节，iv 为 8 字节。</summary>
    /// <param name="cipher">密文字节数组。</param>
    /// <param name="key">16 或 24 字节密钥。</param>
    /// <param name="iv">8 字节 IV。</param>
    /// <returns>明文字节数组。</returns>
    public static byte[] Decrypt(byte[] cipher, byte[] key, byte[] iv)
    {
        if (cipher is null) throw new ArgumentNullException(nameof(cipher));
        if (key is null) throw new ArgumentNullException(nameof(key));
        if (iv is null) throw new ArgumentNullException(nameof(iv));
        return Transform(cipher, key, iv, encrypt: false);
    }

    private static byte[] Transform(byte[] data, byte[] key, byte[] iv, bool encrypt)
    {
        using var tdes = TripleDES.Create();
        tdes.Key = key;
        tdes.IV = iv;
        tdes.Mode = CipherMode.CBC;
        tdes.Padding = PaddingMode.PKCS7;
        using var transform = encrypt ? tdes.CreateEncryptor() : tdes.CreateDecryptor();
        return transform.TransformFinalBlock(data, 0, data.Length);
    }
}
