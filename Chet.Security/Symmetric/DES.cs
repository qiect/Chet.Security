namespace Chet.Security;

/// <summary>
/// DES 对称加密工具类，使用 CBC 模式与 PKCS7 填充。
/// </summary>
/// <remarks>
/// DES 密钥长度仅 64 位（含 8 位奇偶校验，有效强度 56 位），已无法抵御暴力破解，
/// 不应用于新系统，仅作历史兼容与遗留数据解密使用。请优先使用 <see cref="AESHelper"/> 或 <see cref="TripleDESHelper"/>。
/// </remarks>
public static class DESHelper
{
    /// <summary>使用 CBC + PKCS7 加密 UTF-8 明文，返回 Base64 密文。密钥与 IV 均由 <paramref name="key"/> 规范化为 64 位。</summary>
    /// <param name="plain">明文字符串。</param>
    /// <param name="key">密钥（任意长度，将规范化为 64 位；同时用作 IV 来源）。</param>
    /// <returns>Base64 编码的密文。</returns>
    public static string Encrypt(string plain, string key)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(plain, nameof(plain));
        CryptoPolyfill.ThrowIfNullOrEmpty(key, nameof(key));
        var keyBytes = SecurityHelper.NormalizeKey(key, KeyNormalizeMode.Hash, 64);
        var ivBytes = SecurityHelper.NormalizeKey(key, KeyNormalizeMode.Hash, 64);
        var cipher = Encrypt(Encoding.UTF8.GetBytes(plain), keyBytes, ivBytes);
        return Convert.ToBase64String(cipher);
    }

    /// <summary>解密 Base64 密文为 UTF-8 明文。密钥与 IV 均由 <paramref name="key"/> 规范化为 64 位。</summary>
    /// <param name="cipherBase64">Base64 编码的密文。</param>
    /// <param name="key">密钥（任意长度，将规范化为 64 位；同时用作 IV 来源）。</param>
    /// <returns>UTF-8 明文字符串。</returns>
    public static string Decrypt(string cipherBase64, string key)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(cipherBase64, nameof(cipherBase64));
        CryptoPolyfill.ThrowIfNullOrEmpty(key, nameof(key));
        var keyBytes = SecurityHelper.NormalizeKey(key, KeyNormalizeMode.Hash, 64);
        var ivBytes = SecurityHelper.NormalizeKey(key, KeyNormalizeMode.Hash, 64);
        var plain = Decrypt(Convert.FromBase64String(cipherBase64), keyBytes, ivBytes);
        return Encoding.UTF8.GetString(plain);
    }

    /// <summary>使用 CBC + PKCS7 加密字节数组。要求 key/iv 各 8 字节。</summary>
    /// <param name="plain">明文字节数组。</param>
    /// <param name="key">8 字节密钥。</param>
    /// <param name="iv">8 字节 IV。</param>
    /// <returns>密文字节数组。</returns>
    public static byte[] Encrypt(byte[] plain, byte[] key, byte[] iv)
    {
        if (plain is null) throw new ArgumentNullException(nameof(plain));
        if (key is null) throw new ArgumentNullException(nameof(key));
        if (iv is null) throw new ArgumentNullException(nameof(iv));
        return Transform(plain, key, iv, encrypt: true);
    }

    /// <summary>使用 CBC + PKCS7 解密字节数组。要求 key/iv 各 8 字节。</summary>
    /// <param name="cipher">密文字节数组。</param>
    /// <param name="key">8 字节密钥。</param>
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
        try
        {
            using var des = DES.Create();
            des.Key = key;
            des.IV = iv;
            des.Mode = CipherMode.CBC;
            des.Padding = PaddingMode.PKCS7;
            using var transform = encrypt ? des.CreateEncryptor() : des.CreateDecryptor();
            return transform.TransformFinalBlock(data, 0, data.Length);
        }
        catch (CryptographicException ex)
        {
            throw new CryptographicException(
                "DES operation failed: the key may be a known weak/semi-weak key, or the key/IV length is invalid (require 8 bytes each).",
                ex);
        }
    }
}
