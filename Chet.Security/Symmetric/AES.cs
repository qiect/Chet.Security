#if !NET8_0_OR_GREATER
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
#endif

namespace Chet.Security;

/// <summary>
/// AES 对称加密工具类，支持 CBC/ECB（PKCS7 填充）与 GCM 模式。
/// </summary>
/// <remarks>
/// CBC/ECB 使用 BCL <see cref="Aes"/> 实现；GCM 在 net8 下使用 <see cref="AesGcm"/>，
/// 在 netstandard2.1 下回退至 BouncyCastle <c>GcmBlockCipher</c>。GCM 输出格式为 <c>密文 || 16 字节 Tag</c>。
/// </remarks>
public static class AESHelper
{
    /// <summary>使用指定模式加密 UTF-8 明文，返回 Base64 密文。密钥规范化为 256 位，IV 规范化为 128 位（ECB 忽略 IV）。</summary>
    /// <param name="plain">明文字符串。</param>
    /// <param name="key">密钥（任意长度，将规范化为 256 位）。</param>
    /// <param name="iv">初始化向量（任意长度，将规范化为 128 位；ECB 模式忽略）。</param>
    /// <param name="mode">加密模式，默认 <see cref="CipherMode.CBC"/>。</param>
    /// <returns>Base64 编码的密文。</returns>
    public static string Encrypt(string plain, string key, string iv, CipherMode mode = CipherMode.CBC)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(plain, nameof(plain));
        CryptoPolyfill.ThrowIfNullOrEmpty(key, nameof(key));
        var keyBytes = SecurityHelper.NormalizeKey(key, KeyNormalizeMode.Hash, 256);
        var ivBytes = mode == CipherMode.ECB
            ? Array.Empty<byte>()
            : SecurityHelper.NormalizeKey(CryptoPolyfill.ThrowIfNullOrEmpty(iv, nameof(iv)), KeyNormalizeMode.Hash, 128);
        var cipher = Encrypt(Encoding.UTF8.GetBytes(plain), keyBytes, ivBytes, mode);
        return Convert.ToBase64String(cipher);
    }

    /// <summary>解密 Base64 密文为 UTF-8 明文。密钥规范化为 256 位，IV 规范化为 128 位（ECB 忽略 IV）。</summary>
    /// <param name="cipherBase64">Base64 编码的密文。</param>
    /// <param name="key">密钥（任意长度，将规范化为 256 位）。</param>
    /// <param name="iv">初始化向量（任意长度，将规范化为 128 位；ECB 模式忽略）。</param>
    /// <param name="mode">加密模式，默认 <see cref="CipherMode.CBC"/>。</param>
    /// <returns>UTF-8 明文字符串。</returns>
    public static string Decrypt(string cipherBase64, string key, string iv, CipherMode mode = CipherMode.CBC)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(cipherBase64, nameof(cipherBase64));
        CryptoPolyfill.ThrowIfNullOrEmpty(key, nameof(key));
        var keyBytes = SecurityHelper.NormalizeKey(key, KeyNormalizeMode.Hash, 256);
        var ivBytes = mode == CipherMode.ECB
            ? Array.Empty<byte>()
            : SecurityHelper.NormalizeKey(CryptoPolyfill.ThrowIfNullOrEmpty(iv, nameof(iv)), KeyNormalizeMode.Hash, 128);
        var plain = Decrypt(Convert.FromBase64String(cipherBase64), keyBytes, ivBytes, mode);
        return Encoding.UTF8.GetString(plain);
    }

    /// <summary>使用指定模式加密字节数组。仅支持 CBC 与 ECB，填充固定为 PKCS7。</summary>
    /// <param name="plain">明文字节数组。</param>
    /// <param name="key">密钥字节数组（16/24/32 字节）。</param>
    /// <param name="iv">初始化向量（16 字节；ECB 模式可传空）。</param>
    /// <param name="mode">加密模式，默认 <see cref="CipherMode.CBC"/>。</param>
    /// <returns>密文字节数组。</returns>
    public static byte[] Encrypt(byte[] plain, byte[] key, byte[] iv, CipherMode mode = CipherMode.CBC)
    {
        if (plain is null) throw new ArgumentNullException(nameof(plain));
        if (key is null) throw new ArgumentNullException(nameof(key));
        if (mode != CipherMode.CBC && mode != CipherMode.ECB)
            throw new NotSupportedException($"AES helper only supports CBC and ECB modes, mode '{mode}' is not supported.");
        if (mode != CipherMode.ECB && iv is null) throw new ArgumentNullException(nameof(iv));
        return Transform(plain, key, iv, mode, encrypt: true);
    }

    /// <summary>使用指定模式解密字节数组。仅支持 CBC 与 ECB，填充固定为 PKCS7。</summary>
    /// <param name="cipher">密文字节数组。</param>
    /// <param name="key">密钥字节数组（16/24/32 字节）。</param>
    /// <param name="iv">初始化向量（16 字节；ECB 模式可传空）。</param>
    /// <param name="mode">加密模式，默认 <see cref="CipherMode.CBC"/>。</param>
    /// <returns>明文字节数组。</returns>
    public static byte[] Decrypt(byte[] cipher, byte[] key, byte[] iv, CipherMode mode = CipherMode.CBC)
    {
        if (cipher is null) throw new ArgumentNullException(nameof(cipher));
        if (key is null) throw new ArgumentNullException(nameof(key));
        if (mode != CipherMode.CBC && mode != CipherMode.ECB)
            throw new NotSupportedException($"AES helper only supports CBC and ECB modes, mode '{mode}' is not supported.");
        if (mode != CipherMode.ECB && iv is null) throw new ArgumentNullException(nameof(iv));
        return Transform(cipher, key, iv, mode, encrypt: false);
    }

    private static byte[] Transform(byte[] data, byte[] key, byte[] iv, CipherMode mode, bool encrypt)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = mode;
        aes.Padding = PaddingMode.PKCS7;
        if (mode != CipherMode.ECB && iv != null)
            aes.IV = iv;
        using var transform = encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor();
        return transform.TransformFinalBlock(data, 0, data.Length);
    }

    /// <summary>使用 AES-GCM 加密 UTF-8 明文，返回 Base64 密文（密文 || 16 字节 Tag）。密钥规范化为 256 位，nonce 规范化为 96 位。</summary>
    /// <param name="plain">明文字符串。</param>
    /// <param name="key">密钥（任意长度，将规范化为 256 位）。</param>
    /// <param name="nonce">12 字节 nonce（任意长度，将规范化为 96 位）。</param>
    /// <returns>Base64 编码的 <c>密文 || Tag</c>。</returns>
    public static string EncryptGCM(string plain, string key, string nonce)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(plain, nameof(plain));
        CryptoPolyfill.ThrowIfNullOrEmpty(key, nameof(key));
        CryptoPolyfill.ThrowIfNullOrEmpty(nonce, nameof(nonce));
        var keyBytes = SecurityHelper.NormalizeKey(key, KeyNormalizeMode.Hash, 256);
        var nonceBytes = SecurityHelper.NormalizeKey(nonce, KeyNormalizeMode.Hash, 96);
        var cipher = EncryptGCM(Encoding.UTF8.GetBytes(plain), keyBytes, nonceBytes);
        return Convert.ToBase64String(cipher);
    }

    /// <summary>解密 AES-GCM 的 Base64 密文（密文 || 16 字节 Tag）为 UTF-8 明文。密钥规范化为 256 位，nonce 规范化为 96 位。</summary>
    /// <param name="cipherBase64">Base64 编码的 <c>密文 || Tag</c>。</param>
    /// <param name="key">密钥（任意长度，将规范化为 256 位）。</param>
    /// <param name="nonce">12 字节 nonce（任意长度，将规范化为 96 位）。</param>
    /// <returns>UTF-8 明文字符串。</returns>
    public static string DecryptGCM(string cipherBase64, string key, string nonce)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(cipherBase64, nameof(cipherBase64));
        CryptoPolyfill.ThrowIfNullOrEmpty(key, nameof(key));
        CryptoPolyfill.ThrowIfNullOrEmpty(nonce, nameof(nonce));
        var keyBytes = SecurityHelper.NormalizeKey(key, KeyNormalizeMode.Hash, 256);
        var nonceBytes = SecurityHelper.NormalizeKey(nonce, KeyNormalizeMode.Hash, 96);
        var plain = DecryptGCM(Convert.FromBase64String(cipherBase64), keyBytes, nonceBytes);
        return Encoding.UTF8.GetString(plain);
    }

#if NET8_0_OR_GREATER
    /// <summary>使用 AES-GCM 加密字节数组，返回 <c>密文 || 16 字节 Tag</c>。</summary>
    /// <param name="plain">明文字节数组。</param>
    /// <param name="key">密钥字节数组（16/24/32 字节）。</param>
    /// <param name="nonce">12 字节 nonce。</param>
    /// <returns>密文与 16 字节 Tag 的拼接字节数组。</returns>
    public static byte[] EncryptGCM(byte[] plain, byte[] key, byte[] nonce)
    {
        if (plain is null) throw new ArgumentNullException(nameof(plain));
        if (key is null) throw new ArgumentNullException(nameof(key));
        if (nonce is null) throw new ArgumentNullException(nameof(nonce));
        var tag = new byte[16];
        var ciphertext = new byte[plain.Length];
        using var gcm = new AesGcm(key, 16);
        gcm.Encrypt(nonce, plain, ciphertext, tag, null);
        var result = new byte[ciphertext.Length + tag.Length];
        Buffer.BlockCopy(ciphertext, 0, result, 0, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, ciphertext.Length, tag.Length);
        return result;
    }

    /// <summary>解密 AES-GCM 密文（<c>密文 || 16 字节 Tag</c>）。Tag 校验失败时抛出 <see cref="CryptographicException"/>。</summary>
    /// <param name="cipher">密文与 16 字节 Tag 的拼接字节数组。</param>
    /// <param name="key">密钥字节数组（16/24/32 字节）。</param>
    /// <param name="nonce">12 字节 nonce。</param>
    /// <returns>明文字节数组。</returns>
    public static byte[] DecryptGCM(byte[] cipher, byte[] key, byte[] nonce)
    {
        if (cipher is null) throw new ArgumentNullException(nameof(cipher));
        if (key is null) throw new ArgumentNullException(nameof(key));
        if (nonce is null) throw new ArgumentNullException(nameof(nonce));
        if (cipher.Length < 16) throw new ArgumentException("Ciphertext is too short to contain a 16-byte GCM tag.", nameof(cipher));
        int ctLen = cipher.Length - 16;
        var ciphertext = new byte[ctLen];
        var tag = new byte[16];
        Buffer.BlockCopy(cipher, 0, ciphertext, 0, ctLen);
        Buffer.BlockCopy(cipher, ctLen, tag, 0, 16);
        var plain = new byte[ctLen];
        using var gcm = new AesGcm(key, 16);
        gcm.Decrypt(nonce, ciphertext, tag, plain, null);
        return plain;
    }
#else
    /// <summary>使用 AES-GCM（BouncyCastle）加密字节数组，返回 <c>密文 || 16 字节 Tag</c>。</summary>
    /// <param name="plain">明文字节数组。</param>
    /// <param name="key">密钥字节数组（16/24/32 字节）。</param>
    /// <param name="nonce">12 字节 nonce。</param>
    /// <returns>密文与 16 字节 Tag 的拼接字节数组。</returns>
    public static byte[] EncryptGCM(byte[] plain, byte[] key, byte[] nonce)
    {
        if (plain is null) throw new ArgumentNullException(nameof(plain));
        if (key is null) throw new ArgumentNullException(nameof(key));
        if (nonce is null) throw new ArgumentNullException(nameof(nonce));
        var cipher = new GcmBlockCipher(new AesEngine());
        cipher.Init(true, new AeadParameters(new KeyParameter(key), 128, nonce));
        return RunAead(cipher, plain);
    }

    /// <summary>解密 AES-GCM（BouncyCastle）密文（<c>密文 || 16 字节 Tag</c>）。Tag 校验失败时抛出异常。</summary>
    /// <param name="cipher">密文与 16 字节 Tag 的拼接字节数组。</param>
    /// <param name="key">密钥字节数组（16/24/32 字节）。</param>
    /// <param name="nonce">12 字节 nonce。</param>
    /// <returns>明文字节数组。</returns>
    public static byte[] DecryptGCM(byte[] cipher, byte[] key, byte[] nonce)
    {
        if (cipher is null) throw new ArgumentNullException(nameof(cipher));
        if (key is null) throw new ArgumentNullException(nameof(key));
        if (nonce is null) throw new ArgumentNullException(nameof(nonce));
        var aead = new GcmBlockCipher(new AesEngine());
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

    /// <summary>生成 16 字节随机 IV，返回 Base64 字符串。</summary>
    /// <returns>Base64 编码的 16 字节 IV。</returns>
    public static string GenerateIV() => Convert.ToBase64String(SecurityHelper.GenerateRandomBytes(16));

    /// <summary>生成指定长度的随机密钥，返回 Base64 字符串。</summary>
    /// <param name="bitLength">密钥长度（位），默认 256，必须为 8 的正整数倍。</param>
    /// <returns>Base64 编码的密钥。</returns>
    public static string GenerateKey(int bitLength = 256)
    {
        if (bitLength <= 0 || bitLength % 8 != 0)
            throw new ArgumentException("bitLength must be a positive multiple of 8.", nameof(bitLength));
        return Convert.ToBase64String(SecurityHelper.GenerateRandomBytes(bitLength / 8));
    }
}
