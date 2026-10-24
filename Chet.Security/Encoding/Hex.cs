namespace Chet.Security;

/// <summary>
/// 十六进制（Hex）编码/解码工具类，提供字节与十六进制字符串之间的双向转换。
/// </summary>
public static class HexHelper
{
    /// <summary>将字节数组转换为小写十六进制字符串。</summary>
    /// <param name="bytes">输入字节数组。</param>
    /// <returns>小写十六进制字符串（长度为 <paramref name="bytes"/>.Length*2）。</returns>
    public static string Encode(byte[] bytes) => CryptoPolyfill.ToHexLower(bytes);

    /// <summary>将字符串按 UTF-8 编码后转为小写十六进制字符串。</summary>
    public static string EncodeString(string text)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(text, nameof(text));
        return Encode(System.Text.Encoding.UTF8.GetBytes(text));
    }

    /// <summary>将十六进制字符串（大小写均可）解码为字节数组。</summary>
    /// <param name="hex">十六进制字符串，长度必须为偶数。</param>
    public static byte[] Decode(string hex) => CryptoPolyfill.FromHex(hex);

    /// <summary>将十六进制字符串解码为 UTF-8 字符串。</summary>
    public static string DecodeToString(string hex) => System.Text.Encoding.UTF8.GetString(Decode(hex));
}
