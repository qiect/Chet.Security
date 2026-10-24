// Polyfill layer to bridge API differences between netstandard2.1 and net8.0.
// Keeps every encryption class free of #if branches by exposing one consistent surface here.
namespace Chet.Security;

/// <summary>跨目标框架的兼容层，统一 netstandard2.1 与 net8.0 之间的 API 差异。</summary>
internal static class CryptoPolyfill
{
    /// <summary>将字节数组转换为小写十六进制字符串（net8 提供 Convert.ToHexString，netstandard2.1 需自行实现）。</summary>
    public static string ToHexLower(byte[] bytes)
    {
        if (bytes is null) throw new ArgumentNullException(nameof(bytes));
#if NET8_0_OR_GREATER
        return Convert.ToHexString(bytes).ToLowerInvariant();
#else
        var sb = new StringBuilder(bytes.Length * 2);
        for (int i = 0; i < bytes.Length; i++)
            sb.Append(bytes[i].ToString("x2"));
        return sb.ToString();
#endif
    }

    /// <summary>将小写或大写十六进制字符串转换为字节数组。</summary>
    public static byte[] FromHex(string hex)
    {
        if (string.IsNullOrEmpty(hex)) return Array.Empty<byte>();
        if (hex.Length % 2 != 0) throw new ArgumentException("Hex string must have an even length.", nameof(hex));
        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return bytes;
    }

    /// <summary>确认字符串非空，统一抛出 ArgumentException（net8 的 ArgumentException.ThrowIfNullOrEmpty 在 netstandard2.1 不存在）。</summary>
    public static string ThrowIfNullOrEmpty(string? value, string paramName)
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(value);
#else
        if (string.IsNullOrEmpty(value))
            throw new ArgumentException($"'{paramName}' cannot be null or empty.", paramName);
#endif
        return value!;
    }

    /// <summary>仅校验非 null，允许空字符串（摘要类输入空串是合法的密码学操作，应允许计算空消息摘要）。</summary>
    public static string ThrowIfNull(string? value, string paramName)
    {
        if (value is null)
            throw new ArgumentNullException(paramName, $"'{paramName}' cannot be null.");
        return value;
    }

    /// <summary>对 byte[] 做 ReadOnlySpan 兼容切片（保持签名一致）。</summary>
    public static byte[] Slice(byte[] source, int offset, int length)
    {
        if (source is null) throw new ArgumentNullException(nameof(source));
        if (offset < 0 || length < 0 || offset + length > source.Length)
            throw new ArgumentOutOfRangeException();
        var result = new byte[length];
        Buffer.BlockCopy(source, offset, result, 0, length);
        return result;
    }
}
