#if !NET8_0_OR_GREATER
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
#endif

namespace Chet.Security;

/// <summary>
/// ChaCha20-Poly1305 AEAD 认证加密工具类。
/// </summary>
/// <remarks>
/// net8 下使用 BCL <see cref="ChaCha20Poly1305"/>；netstandard2.1 下回退至 BouncyCastle 实现。
/// 输出格式为 <c>密文 || 16 字节 Tag</c>，解密时取末尾 16 字节作为 Tag 进行校验。
/// </remarks>
public static class ChaCha20Poly1305Helper
{
    /// <summary>加密 UTF-8 明文，返回 Base64 密文（<c>密文 || 16 字节 Tag</c>）。密钥规范化为 256 位，nonce 规范化为 96 位。</summary>
    /// <param name="plain">明文字符串。</param>
    /// <param name="key">密钥（任意长度，将规范化为 256 位）。</param>
    /// <param name="nonce">12 字节 nonce（任意长度，将规范化为 96 位）。</param>
    /// <returns>Base64 编码的 <c>密文 || Tag</c>。</returns>
    public static string Encrypt(string plain, string key, string nonce)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(plain, nameof(plain));
        CryptoPolyfill.ThrowIfNullOrEmpty(key, nameof(key));
        CryptoPolyfill.ThrowIfNullOrEmpty(nonce, nameof(nonce));
        var keyBytes = SecurityHelper.NormalizeKey(key, KeyNormalizeMode.Hash, 256);
        var nonceBytes = SecurityHelper.NormalizeKey(nonce, KeyNormalizeMode.Hash, 96);
        var cipher = Encrypt(Encoding.UTF8.GetBytes(plain), keyBytes, nonceBytes);
        return Convert.ToBase64String(cipher);
    }

    /// <summary>解密 Base64 密文（<c>密文 || 16 字节 Tag</c>）为 UTF-8 明文。密钥规范化为 256 位，nonce 规范化为 96 位。</summary>
    /// <param name="cipherBase64">Base64 编码的 <c>密文 || Tag</c>。</param>
    /// <param name="key">密钥（任意长度，将规范化为 256 位）。</param>
    /// <param name="nonce">12 字节 nonce（任意长度，将规范化为 96 位）。</param>
    /// <returns>UTF-8 明文字符串。</returns>
    public static string Decrypt(string cipherBase64, string key, string nonce)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(cipherBase64, nameof(cipherBase64));
        CryptoPolyfill.ThrowIfNullOrEmpty(key, nameof(key));
        CryptoPolyfill.ThrowIfNullOrEmpty(nonce, nameof(nonce));
        var keyBytes = SecurityHelper.NormalizeKey(key, KeyNormalizeMode.Hash, 256);
        var nonceBytes = SecurityHelper.NormalizeKey(nonce, KeyNormalizeMode.Hash, 96);
        var plain = Decrypt(Convert.FromBase64String(cipherBase64), keyBytes, nonceBytes);
        return Encoding.UTF8.GetString(plain);
    }

#if NET8_0_OR_GREATER
    /// <summary>加密字节数组，返回 <c>密文 || 16 字节 Tag</c>。</summary>
    /// <param name="plain">明文字节数组。</param>
    /// <param name="key">32 字节密钥。</param>
    /// <param name="nonce">12 字节 nonce。</param>
    /// <returns>密文与 16 字节 Tag 的拼接字节数组。</returns>
    public static byte[] Encrypt(byte[] plain, byte[] key, byte[] nonce)
    {
        if (plain is null) throw new ArgumentNullException(nameof(plain));
        if (key is null) throw new ArgumentNullException(nameof(key));
        if (nonce is null) throw new ArgumentNullException(nameof(nonce));
        var tag = new byte[16];
        var ciphertext = new byte[plain.Length];
        using var aead = new ChaCha20Poly1305(key);
        aead.Encrypt(nonce, plain, ciphertext, tag, null);
        var result = new byte[ciphertext.Length + tag.Length];
        Buffer.BlockCopy(ciphertext, 0, result, 0, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, ciphertext.Length, tag.Length);
        return result;
    }

    /// <summary>解密密文（<c>密文 || 16 字节 Tag</c>）。Tag 校验失败时抛出 <see cref="CryptographicException"/>。</summary>
    /// <param name="cipher">密文与 16 字节 Tag 的拼接字节数组。</param>
    /// <param name="key">32 字节密钥。</param>
    /// <param name="nonce">12 字节 nonce。</param>
    /// <returns>明文字节数组。</returns>
    public static byte[] Decrypt(byte[] cipher, byte[] key, byte[] nonce)
    {
        if (cipher is null) throw new ArgumentNullException(nameof(cipher));
        if (key is null) throw new ArgumentNullException(nameof(key));
        if (nonce is null) throw new ArgumentNullException(nameof(nonce));
        if (cipher.Length < 16) throw new ArgumentException("Ciphertext is too short to contain a 16-byte Poly1305 tag.", nameof(cipher));
        int ctLen = cipher.Length - 16;
        var ciphertext = new byte[ctLen];
        var tag = new byte[16];
        Buffer.BlockCopy(cipher, 0, ciphertext, 0, ctLen);
        Buffer.BlockCopy(cipher, ctLen, tag, 0, 16);
        var plain = new byte[ctLen];
        using var aead = new ChaCha20Poly1305(key);
        aead.Decrypt(nonce, ciphertext, tag, plain, null);
        return plain;
    }
#else
    /// <summary>加密字节数组（BouncyCastle），返回 <c>密文 || 16 字节 Tag</c>。</summary>
    /// <param name="plain">明文字节数组。</param>
    /// <param name="key">32 字节密钥。</param>
    /// <param name="nonce">12 字节 nonce。</param>
    /// <returns>密文与 16 字节 Tag 的拼接字节数组。</returns>
    public static byte[] Encrypt(byte[] plain, byte[] key, byte[] nonce)
    {
        if (plain is null) throw new ArgumentNullException(nameof(plain));
        if (key is null) throw new ArgumentNullException(nameof(key));
        if (nonce is null) throw new ArgumentNullException(nameof(nonce));
        var cipher = new ChaCha20Poly1305();
        cipher.Init(true, new AeadParameters(new KeyParameter(key), 128, nonce));
        return RunAead(cipher, plain);
    }

    /// <summary>解密密文（<c>密文 || 16 字节 Tag</c>，BouncyCastle）。Tag 校验失败时抛出异常。</summary>
    /// <param name="cipher">密文与 16 字节 Tag 的拼接字节数组。</param>
    /// <param name="key">32 字节密钥。</param>
    /// <param name="nonce">12 字节 nonce。</param>
    /// <returns>明文字节数组。</returns>
    public static byte[] Decrypt(byte[] cipher, byte[] key, byte[] nonce)
    {
        if (cipher is null) throw new ArgumentNullException(nameof(cipher));
        if (key is null) throw new ArgumentNullException(nameof(key));
        if (nonce is null) throw new ArgumentNullException(nameof(nonce));
        var aead = new ChaCha20Poly1305();
        aead.Init(false, new AeadParameters(new KeyParameter(key), 128, nonce));
        return RunAead(aead, cipher);
    }

    private static byte[] RunAead(IAeadCipher cipher, byte[] input)
    {
        int len = cipher.GetOutputSize(input.Length);
        var output = new byte[len];
        int off = cipher.ProcessBytes(input, 0, input.Length, output, 0);
        int final = cipher.DoFinal(output, off);
        int total = off + final;
        if (total == len) return output;
        var trimmed = new byte[total];
        Buffer.BlockCopy(output, 0, trimmed, 0, total);
        return trimmed;
    }
#endif

    /// <summary>生成 12 字节随机 nonce，返回 Base64 字符串。</summary>
    /// <returns>Base64 编码的 12 字节 nonce。</returns>
    public static string GenerateNonce() => Convert.ToBase64String(SecurityHelper.GenerateRandomBytes(12));

    /// <summary>生成 32 字节随机密钥，返回 Base64 字符串。</summary>
    /// <returns>Base64 编码的 32 字节密钥。</returns>
    public static string GenerateKey() => Convert.ToBase64String(SecurityHelper.GenerateRandomBytes(32));
}
