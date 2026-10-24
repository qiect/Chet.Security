namespace Chet.Security;

/// <summary>
/// Base64 编码/解码工具类，提供字符串与字节之间的标准 Base64 转换，并支持自定义码表。
/// </summary>
public static class Base64Helper
{
    /// <summary>标准 Base64 码表。</summary>
    public const string StandardAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// <summary>URL 安全 Base64 码表（将 + 替换为 -，/ 替换为 _）。</summary>
    public const string UrlSafeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// <summary>将字节数组编码为标准 Base64 字符串。</summary>
    public static string Encode(byte[] bytes) => Convert.ToBase64String(bytes);

    /// <summary>将字符串按 UTF-8 编码后转为 Base64。</summary>
    public static string EncodeString(string text)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(text, nameof(text));
        return Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(text));
    }

    /// <summary>将字节数组编码为 URL 安全 Base64（去除填充 =）。</summary>
    public static string EncodeUrlSafe(byte[] bytes)
        => Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    /// <summary>将字符串编码为 URL 安全 Base64。</summary>
    public static string EncodeStringUrlSafe(string text)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(text, nameof(text));
        return EncodeUrlSafe(System.Text.Encoding.UTF8.GetBytes(text));
    }

    /// <summary>将 Base64 字符串（兼容标准与 URL 安全格式）解码为字节数组。</summary>
    public static byte[] Decode(string base64)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(base64, nameof(base64));
        var normalized = base64.Replace('-', '+').Replace('_', '/');
        // 补齐 padding
        switch (normalized.Length % 4)
        {
            case 2: normalized += "=="; break;
            case 3: normalized += "="; break;
            case 1: throw new FormatException("Invalid Base64 length.");
        }
        return Convert.FromBase64String(normalized);
    }

    /// <summary>将 Base64 字符串解码为 UTF-8 字符串。</summary>
    public static string DecodeToString(string base64)
        => System.Text.Encoding.UTF8.GetString(Decode(base64));
}
