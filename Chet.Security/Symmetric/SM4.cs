using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace Chet.Security;

/// <summary>
/// SM4 国密对称加密工具类，采用 CBC 模式与 PKCS7 填充，基于 BouncyCastle <c>SM4Engine</c> 实现。
/// </summary>
public static class SM4Helper
{
    /// <summary>使用 CBC + PKCS7 加密 UTF-8 明文，返回 Base64 密文。密钥与 IV 均规范化为 128 位。</summary>
    /// <param name="plain">明文字符串。</param>
    /// <param name="key">密钥（任意长度，将规范化为 128 位）。</param>
    /// <param name="iv">初始化向量（任意长度，将规范化为 128 位）。</param>
    /// <returns>Base64 编码的密文。</returns>
    public static string Encrypt(string plain, string key, string iv)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(plain, nameof(plain));
        CryptoPolyfill.ThrowIfNullOrEmpty(key, nameof(key));
        CryptoPolyfill.ThrowIfNullOrEmpty(iv, nameof(iv));
        var keyBytes = SecurityHelper.NormalizeKey(key, KeyNormalizeMode.Hash, 128);
        var ivBytes = SecurityHelper.NormalizeKey(iv, KeyNormalizeMode.Hash, 128);
        var cipher = Encrypt(Encoding.UTF8.GetBytes(plain), keyBytes, ivBytes);
        return Convert.ToBase64String(cipher);
    }

    /// <summary>解密 Base64 密文为 UTF-8 明文。密钥与 IV 均规范化为 128 位。</summary>
    /// <param name="cipherBase64">Base64 编码的密文。</param>
    /// <param name="key">密钥（任意长度，将规范化为 128 位）。</param>
    /// <param name="iv">初始化向量（任意长度，将规范化为 128 位）。</param>
    /// <returns>UTF-8 明文字符串。</returns>
    public static string Decrypt(string cipherBase64, string key, string iv)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(cipherBase64, nameof(cipherBase64));
        CryptoPolyfill.ThrowIfNullOrEmpty(key, nameof(key));
        CryptoPolyfill.ThrowIfNullOrEmpty(iv, nameof(iv));
        var keyBytes = SecurityHelper.NormalizeKey(key, KeyNormalizeMode.Hash, 128);
        var ivBytes = SecurityHelper.NormalizeKey(iv, KeyNormalizeMode.Hash, 128);
        var plain = Decrypt(Convert.FromBase64String(cipherBase64), keyBytes, ivBytes);
        return Encoding.UTF8.GetString(plain);
    }

    /// <summary>使用 CBC + PKCS7 加密字节数组。要求 key/iv 各 16 字节。</summary>
    /// <param name="plain">明文字节数组。</param>
    /// <param name="key">16 字节密钥。</param>
    /// <param name="iv">16 字节 IV。</param>
    /// <returns>密文字节数组。</returns>
    public static byte[] Encrypt(byte[] plain, byte[] key, byte[] iv)
    {
        if (plain is null) throw new ArgumentNullException(nameof(plain));
        if (key is null) throw new ArgumentNullException(nameof(key));
        if (iv is null) throw new ArgumentNullException(nameof(iv));
        return Process(plain, key, iv, encrypt: true);
    }

    /// <summary>使用 CBC + PKCS7 解密字节数组。要求 key/iv 各 16 字节。</summary>
    /// <param name="cipher">密文字节数组。</param>
    /// <param name="key">16 字节密钥。</param>
    /// <param name="iv">16 字节 IV。</param>
    /// <returns>明文字节数组。</returns>
    public static byte[] Decrypt(byte[] cipher, byte[] key, byte[] iv)
    {
        if (cipher is null) throw new ArgumentNullException(nameof(cipher));
        if (key is null) throw new ArgumentNullException(nameof(key));
        if (iv is null) throw new ArgumentNullException(nameof(iv));
        return Process(cipher, key, iv, encrypt: false);
    }

    private static byte[] Process(byte[] data, byte[] key, byte[] iv, bool encrypt)
    {
        IBufferedCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new SM4Engine()), new Pkcs7Padding());
        cipher.Init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
        int len = cipher.GetOutputSize(data.Length);
        var output = new byte[len];
        int off = cipher.ProcessBytes(data, 0, data.Length, output, 0);
        int final = cipher.DoFinal(output, off);
        int total = off + final;
        if (total == len) return output;
        var trimmed = new byte[total];
        Buffer.BlockCopy(output, 0, trimmed, 0, total);
        return trimmed;
    }
}
