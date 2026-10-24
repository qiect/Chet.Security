using Org.BouncyCastle.Crypto.Digests;

namespace Chet.Security;

/// <summary>
/// Blake2 摘要工具类，使用 BouncyCastle 的 <see cref="Blake2bDigest"/>/<see cref="Blake2sDigest"/> 实现。
/// Blake2b 默认输出 512 位（64 字节），Blake2s 默认输出 256 位（32 字节）。
/// 支持可选密钥（keyed Blake2b）变体；密钥为 null 或空数组时退回无密钥变体。
/// </summary>
public static class Blake2Helper
{
    /// <summary>计算字节数组的 Blake2b 摘要（512 位，无密钥），返回小写十六进制字符串。</summary>
    /// <param name="data">待计算的字节数据。</param>
    /// <returns>128 字符长度的小写十六进制摘要。</returns>
    public static string ComputeBlake2b(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        return CryptoPolyfill.ToHexLower(ComputeBlake2bBytes(data));
    }

    /// <summary>将字符串按 UTF-8 编码后计算 Blake2b 摘要（512 位，无密钥），返回小写十六进制字符串。</summary>
    /// <param name="text">待计算的字符串。</param>
    /// <returns>128 字符长度的小写十六进制摘要。</returns>
    public static string ComputeBlake2b(string text)
    {
        CryptoPolyfill.ThrowIfNull(text, nameof(text));
        return ComputeBlake2b(Encoding.UTF8.GetBytes(text));
    }

    /// <summary>计算字节数组与密钥的 keyed Blake2b 摘要（512 位），返回小写十六进制字符串。</summary>
    /// <param name="data">待计算的字节数据。</param>
    /// <param name="key">HMAC 密钥；为 null 或空数组时使用无密钥变体。</param>
    /// <returns>128 字符长度的小写十六进制摘要。</returns>
    public static string ComputeBlake2b(byte[] data, byte[] key)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        return CryptoPolyfill.ToHexLower(ComputeBlake2bBytes(data, key));
    }

    /// <summary>计算字节数组的 Blake2s 摘要（256 位，无密钥），返回小写十六进制字符串。</summary>
    /// <param name="data">待计算的字节数据。</param>
    /// <returns>64 字符长度的小写十六进制摘要。</returns>
    public static string ComputeBlake2s(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        return CryptoPolyfill.ToHexLower(ComputeBlake2sBytes(data));
    }

    /// <summary>将字符串按 UTF-8 编码后计算 Blake2s 摘要（256 位，无密钥），返回小写十六进制字符串。</summary>
    /// <param name="text">待计算的字符串。</param>
    /// <returns>64 字符长度的小写十六进制摘要。</returns>
    public static string ComputeBlake2s(string text)
    {
        CryptoPolyfill.ThrowIfNull(text, nameof(text));
        return ComputeBlake2s(Encoding.UTF8.GetBytes(text));
    }

    /// <summary>计算字节数组的 Blake2b 摘要（512 位，无密钥），返回原始字节数组（64 字节）。</summary>
    /// <param name="data">待计算的字节数据。</param>
    /// <returns>64 字节长度的原始摘要。</returns>
    public static byte[] ComputeBlake2bBytes(byte[] data) => ComputeBlake2bBytes(data, null);

    /// <summary>计算字节数组与密钥的 keyed Blake2b 摘要（512 位），返回原始字节数组（64 字节）。</summary>
    /// <param name="data">待计算的字节数据。</param>
    /// <param name="key">HMAC 密钥；为 null 或空数组时使用无密钥变体。</param>
    /// <returns>64 字节长度的原始摘要。</returns>
    public static byte[] ComputeBlake2bBytes(byte[] data, byte[] key)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        Blake2bDigest digest = key is null || key.Length == 0
            ? new Blake2bDigest()
            : new Blake2bDigest(key);
        digest.BlockUpdate(data, 0, data.Length);
        var output = new byte[digest.GetDigestSize()];
        digest.DoFinal(output, 0);
        return output;
    }

    /// <summary>计算字节数组的 Blake2s 摘要（256 位，无密钥），返回原始字节数组（32 字节）。</summary>
    /// <param name="data">待计算的字节数据。</param>
    /// <returns>32 字节长度的原始摘要。</returns>
    public static byte[] ComputeBlake2sBytes(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        var digest = new Blake2sDigest();
        digest.BlockUpdate(data, 0, data.Length);
        var output = new byte[digest.GetDigestSize()];
        digest.DoFinal(output, 0);
        return output;
    }
}
