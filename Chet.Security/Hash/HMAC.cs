using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Chet.Security;

/// <summary>
/// HMAC 摘要工具类，提供基于 MD5/SHA-1/SHA-256/SHA-384/SHA-512/SM3 的 HMAC 计算。
/// 非 SM3 系列使用 BCL 的 <see cref="HMACMD5"/>/<see cref="HMACSHA256"/> 等实现；
/// HMAC-SM3 使用 BouncyCastle 的 <see cref="HMac"/> + <see cref="SM3Digest"/> 实现。
/// </summary>
public static class HMACHelper
{
    // ---------------- HMAC-MD5 ----------------

    /// <summary>计算字节数组与密钥的 HMAC-MD5，返回小写十六进制字符串。</summary>
    /// <param name="data">待计算的消息数据。</param>
    /// <param name="key">HMAC 密钥。</param>
    /// <returns>32 字符长度的小写十六进制 MAC。</returns>
    public static string ComputeHmacMD5(byte[] data, byte[] key)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (key is null) throw new ArgumentNullException(nameof(key));
        using var hmac = new HMACMD5(key);
        return CryptoPolyfill.ToHexLower(hmac.ComputeHash(data));
    }

    /// <summary>将消息字符串与密钥字符串（均为 UTF-8 编码）计算 HMAC-MD5，返回小写十六进制字符串。</summary>
    /// <param name="text">待计算的消息字符串。</param>
    /// <param name="key">HMAC 密钥字符串。</param>
    /// <returns>32 字符长度的小写十六进制 MAC。</returns>
    public static string ComputeHmacMD5(string text, string key)
    {
        CryptoPolyfill.ThrowIfNull(text, nameof(text));
        CryptoPolyfill.ThrowIfNullOrEmpty(key, nameof(key));
        return ComputeHmacMD5(Encoding.UTF8.GetBytes(text), Encoding.UTF8.GetBytes(key));
    }

    /// <summary>计算字节数组与密钥的 HMAC-MD5，返回原始字节数组（16 字节）。</summary>
    /// <param name="data">待计算的消息数据。</param>
    /// <param name="key">HMAC 密钥。</param>
    /// <returns>16 字节长度的原始 MAC。</returns>
    public static byte[] ComputeHmacMD5Bytes(byte[] data, byte[] key)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (key is null) throw new ArgumentNullException(nameof(key));
        using var hmac = new HMACMD5(key);
        return hmac.ComputeHash(data);
    }

    // ---------------- HMAC-SHA1 ----------------

    /// <summary>计算字节数组与密钥的 HMAC-SHA1，返回小写十六进制字符串。</summary>
    /// <param name="data">待计算的消息数据。</param>
    /// <param name="key">HMAC 密钥。</param>
    /// <returns>40 字符长度的小写十六进制 MAC。</returns>
    public static string ComputeHmacSHA1(byte[] data, byte[] key)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (key is null) throw new ArgumentNullException(nameof(key));
        using var hmac = new HMACSHA1(key);
        return CryptoPolyfill.ToHexLower(hmac.ComputeHash(data));
    }

    /// <summary>将消息字符串与密钥字符串（均为 UTF-8 编码）计算 HMAC-SHA1，返回小写十六进制字符串。</summary>
    /// <param name="text">待计算的消息字符串。</param>
    /// <param name="key">HMAC 密钥字符串。</param>
    /// <returns>40 字符长度的小写十六进制 MAC。</returns>
    public static string ComputeHmacSHA1(string text, string key)
    {
        CryptoPolyfill.ThrowIfNull(text, nameof(text));
        CryptoPolyfill.ThrowIfNullOrEmpty(key, nameof(key));
        return ComputeHmacSHA1(Encoding.UTF8.GetBytes(text), Encoding.UTF8.GetBytes(key));
    }

    /// <summary>计算字节数组与密钥的 HMAC-SHA1，返回原始字节数组（20 字节）。</summary>
    /// <param name="data">待计算的消息数据。</param>
    /// <param name="key">HMAC 密钥。</param>
    /// <returns>20 字节长度的原始 MAC。</returns>
    public static byte[] ComputeHmacSHA1Bytes(byte[] data, byte[] key)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (key is null) throw new ArgumentNullException(nameof(key));
        using var hmac = new HMACSHA1(key);
        return hmac.ComputeHash(data);
    }

    // ---------------- HMAC-SHA256 ----------------

    /// <summary>计算字节数组与密钥的 HMAC-SHA256，返回小写十六进制字符串。</summary>
    /// <param name="data">待计算的消息数据。</param>
    /// <param name="key">HMAC 密钥。</param>
    /// <returns>64 字符长度的小写十六进制 MAC。</returns>
    public static string ComputeHmacSHA256(byte[] data, byte[] key)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (key is null) throw new ArgumentNullException(nameof(key));
        using var hmac = new HMACSHA256(key);
        return CryptoPolyfill.ToHexLower(hmac.ComputeHash(data));
    }

    /// <summary>将消息字符串与密钥字符串（均为 UTF-8 编码）计算 HMAC-SHA256，返回小写十六进制字符串。</summary>
    /// <param name="text">待计算的消息字符串。</param>
    /// <param name="key">HMAC 密钥字符串。</param>
    /// <returns>64 字符长度的小写十六进制 MAC。</returns>
    public static string ComputeHmacSHA256(string text, string key)
    {
        CryptoPolyfill.ThrowIfNull(text, nameof(text));
        CryptoPolyfill.ThrowIfNullOrEmpty(key, nameof(key));
        return ComputeHmacSHA256(Encoding.UTF8.GetBytes(text), Encoding.UTF8.GetBytes(key));
    }

    /// <summary>计算字节数组与密钥的 HMAC-SHA256，返回原始字节数组（32 字节）。</summary>
    /// <param name="data">待计算的消息数据。</param>
    /// <param name="key">HMAC 密钥。</param>
    /// <returns>32 字节长度的原始 MAC。</returns>
    public static byte[] ComputeHmacSHA256Bytes(byte[] data, byte[] key)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (key is null) throw new ArgumentNullException(nameof(key));
        using var hmac = new HMACSHA256(key);
        return hmac.ComputeHash(data);
    }

    // ---------------- HMAC-SHA384 ----------------

    /// <summary>计算字节数组与密钥的 HMAC-SHA384，返回小写十六进制字符串。</summary>
    /// <param name="data">待计算的消息数据。</param>
    /// <param name="key">HMAC 密钥。</param>
    /// <returns>96 字符长度的小写十六进制 MAC。</returns>
    public static string ComputeHmacSHA384(byte[] data, byte[] key)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (key is null) throw new ArgumentNullException(nameof(key));
        using var hmac = new HMACSHA384(key);
        return CryptoPolyfill.ToHexLower(hmac.ComputeHash(data));
    }

    /// <summary>将消息字符串与密钥字符串（均为 UTF-8 编码）计算 HMAC-SHA384，返回小写十六进制字符串。</summary>
    /// <param name="text">待计算的消息字符串。</param>
    /// <param name="key">HMAC 密钥字符串。</param>
    /// <returns>96 字符长度的小写十六进制 MAC。</returns>
    public static string ComputeHmacSHA384(string text, string key)
    {
        CryptoPolyfill.ThrowIfNull(text, nameof(text));
        CryptoPolyfill.ThrowIfNullOrEmpty(key, nameof(key));
        return ComputeHmacSHA384(Encoding.UTF8.GetBytes(text), Encoding.UTF8.GetBytes(key));
    }

    /// <summary>计算字节数组与密钥的 HMAC-SHA384，返回原始字节数组（48 字节）。</summary>
    /// <param name="data">待计算的消息数据。</param>
    /// <param name="key">HMAC 密钥。</param>
    /// <returns>48 字节长度的原始 MAC。</returns>
    public static byte[] ComputeHmacSHA384Bytes(byte[] data, byte[] key)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (key is null) throw new ArgumentNullException(nameof(key));
        using var hmac = new HMACSHA384(key);
        return hmac.ComputeHash(data);
    }

    // ---------------- HMAC-SHA512 ----------------

    /// <summary>计算字节数组与密钥的 HMAC-SHA512，返回小写十六进制字符串。</summary>
    /// <param name="data">待计算的消息数据。</param>
    /// <param name="key">HMAC 密钥。</param>
    /// <returns>128 字符长度的小写十六进制 MAC。</returns>
    public static string ComputeHmacSHA512(byte[] data, byte[] key)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (key is null) throw new ArgumentNullException(nameof(key));
        using var hmac = new HMACSHA512(key);
        return CryptoPolyfill.ToHexLower(hmac.ComputeHash(data));
    }

    /// <summary>将消息字符串与密钥字符串（均为 UTF-8 编码）计算 HMAC-SHA512，返回小写十六进制字符串。</summary>
    /// <param name="text">待计算的消息字符串。</param>
    /// <param name="key">HMAC 密钥字符串。</param>
    /// <returns>128 字符长度的小写十六进制 MAC。</returns>
    public static string ComputeHmacSHA512(string text, string key)
    {
        CryptoPolyfill.ThrowIfNull(text, nameof(text));
        CryptoPolyfill.ThrowIfNullOrEmpty(key, nameof(key));
        return ComputeHmacSHA512(Encoding.UTF8.GetBytes(text), Encoding.UTF8.GetBytes(key));
    }

    /// <summary>计算字节数组与密钥的 HMAC-SHA512，返回原始字节数组（64 字节）。</summary>
    /// <param name="data">待计算的消息数据。</param>
    /// <param name="key">HMAC 密钥。</param>
    /// <returns>64 字节长度的原始 MAC。</returns>
    public static byte[] ComputeHmacSHA512Bytes(byte[] data, byte[] key)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (key is null) throw new ArgumentNullException(nameof(key));
        using var hmac = new HMACSHA512(key);
        return hmac.ComputeHash(data);
    }

    // ---------------- HMAC-SM3 ----------------

    /// <summary>计算字节数组与密钥的 HMAC-SM3（BouncyCastle 实现），返回小写十六进制字符串。</summary>
    /// <param name="data">待计算的消息数据。</param>
    /// <param name="key">HMAC 密钥。</param>
    /// <returns>64 字符长度的小写十六进制 MAC。</returns>
    public static string ComputeHmacSM3(byte[] data, byte[] key)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (key is null) throw new ArgumentNullException(nameof(key));
        return CryptoPolyfill.ToHexLower(ComputeHmacSM3Bytes(data, key));
    }

    /// <summary>将消息字符串与密钥字符串（均为 UTF-8 编码）计算 HMAC-SM3，返回小写十六进制字符串。</summary>
    /// <param name="text">待计算的消息字符串。</param>
    /// <param name="key">HMAC 密钥字符串。</param>
    /// <returns>64 字符长度的小写十六进制 MAC。</returns>
    public static string ComputeHmacSM3(string text, string key)
    {
        CryptoPolyfill.ThrowIfNull(text, nameof(text));
        CryptoPolyfill.ThrowIfNullOrEmpty(key, nameof(key));
        return ComputeHmacSM3(Encoding.UTF8.GetBytes(text), Encoding.UTF8.GetBytes(key));
    }

    /// <summary>计算字节数组与密钥的 HMAC-SM3（BouncyCastle 实现），返回原始字节数组（32 字节）。</summary>
    /// <param name="data">待计算的消息数据。</param>
    /// <param name="key">HMAC 密钥。</param>
    /// <returns>32 字节长度的原始 MAC。</returns>
    public static byte[] ComputeHmacSM3Bytes(byte[] data, byte[] key)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (key is null) throw new ArgumentNullException(nameof(key));
        var hmac = new HMac(new SM3Digest());
        hmac.Init(new KeyParameter(key));
        hmac.BlockUpdate(data, 0, data.Length);
        var output = new byte[hmac.GetMacSize()];
        hmac.DoFinal(output, 0);
        return output;
    }
}
