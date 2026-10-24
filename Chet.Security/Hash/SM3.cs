using Org.BouncyCastle.Crypto.Digests;

namespace Chet.Security;

/// <summary>
/// SM3 国密摘要工具类，使用 BouncyCastle 的 <see cref="SM3Digest"/> 实现国密哈希算法。
/// 输出长度固定为 256 位（32 字节，64 字符十六进制）。
/// </summary>
public static class SM3Helper
{
    /// <summary>计算字节数组的 SM3 摘要，返回小写十六进制字符串。</summary>
    /// <param name="data">待计算的字节数据。</param>
    /// <returns>64 字符长度的小写十六进制摘要。</returns>
    public static string ComputeHash(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        return CryptoPolyfill.ToHexLower(ComputeHashBytes(data));
    }

    /// <summary>将字符串按 UTF-8 编码后计算 SM3 摘要，返回小写十六进制字符串。</summary>
    /// <param name="text">待计算的字符串。</param>
    /// <returns>64 字符长度的小写十六进制摘要。</returns>
    public static string ComputeHash(string text)
    {
        CryptoPolyfill.ThrowIfNull(text, nameof(text));
        return ComputeHash(Encoding.UTF8.GetBytes(text));
    }

    /// <summary>计算字节数组的 SM3 摘要，返回 Base64 字符串。</summary>
    /// <param name="data">待计算的字节数据。</param>
    /// <returns>Base64 编码的摘要字符串。</returns>
    public static string ComputeHashBase64(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        return Convert.ToBase64String(ComputeHashBytes(data));
    }

    /// <summary>将字符串按 UTF-8 编码后计算 SM3 摘要，返回 Base64 字符串。</summary>
    /// <param name="text">待计算的字符串。</param>
    /// <returns>Base64 编码的摘要字符串。</returns>
    public static string ComputeHashBase64(string text)
    {
        CryptoPolyfill.ThrowIfNull(text, nameof(text));
        return ComputeHashBase64(Encoding.UTF8.GetBytes(text));
    }

    /// <summary>计算字节数组的 SM3 摘要，返回原始字节数组（32 字节）。</summary>
    /// <param name="data">待计算的字节数据。</param>
    /// <returns>32 字节长度的原始摘要。</returns>
    public static byte[] ComputeHashBytes(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        var digest = new SM3Digest();
        digest.BlockUpdate(data, 0, data.Length);
        var output = new byte[digest.GetDigestSize()];
        digest.DoFinal(output, 0);
        return output;
    }
}
