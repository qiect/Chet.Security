namespace Chet.Security;

/// <summary>
/// Base32 编码/解码工具类（RFC 4648），使用 A-Z2-7 码表，常用于对大小写不敏感场景与 TOTP 密钥编码。
/// </summary>
public static class Base32Helper
{
    /// <summary>标准 Base32 码表（RFC 4648）。</summary>
    public const string StandardAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /// <summary>将字节数组编码为 Base32 字符串（带 = 填充）。</summary>
    public static string Encode(byte[] bytes)
    {
        if (bytes is null) throw new ArgumentNullException(nameof(bytes));
        if (bytes.Length == 0) return string.Empty;

        var sb = new StringBuilder((bytes.Length + 4) / 5 * 8);
        int buffer = 0;
        int bitsLeft = 0;

        foreach (var b in bytes)
        {
            buffer = (buffer << 8) | b;
            bitsLeft += 8;
            while (bitsLeft >= 5)
            {
                int index = (buffer >> (bitsLeft - 5)) & 0x1F;
                sb.Append(StandardAlphabet[index]);
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0)
        {
            int index = (buffer << (5 - bitsLeft)) & 0x1F;
            sb.Append(StandardAlphabet[index]);
        }
        // 填充到 8 的倍数
        int pad = (8 - (sb.Length % 8)) % 8;
        sb.Append('=', pad);
        return sb.ToString();
    }

    /// <summary>将字符串按 UTF-8 编码后转为 Base32。</summary>
    public static string EncodeString(string text)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(text, nameof(text));
        return Encode(System.Text.Encoding.UTF8.GetBytes(text));
    }

    /// <summary>将 Base32 字符串解码为字节数组（大小写不敏感，忽略空白）。</summary>
    public static byte[] Decode(string base32)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(base32, nameof(base32));
        base32 = base32.TrimEnd('=').Replace(" ", "").ToUpperInvariant();
        var bytes = new List<byte>(base32.Length * 5 / 8 + 1);
        int buffer = 0;
        int bitsLeft = 0;

        foreach (var c in base32)
        {
            int value = StandardAlphabet.IndexOf(c);
            if (value < 0) throw new FormatException($"Invalid Base32 character: {c}");
            buffer = (buffer << 5) | value;
            bitsLeft += 5;
            if (bitsLeft >= 8)
            {
                bytes.Add((byte)((buffer >> (bitsLeft - 8)) & 0xFF));
                bitsLeft -= 8;
            }
        }
        return bytes.ToArray();
    }

    /// <summary>将 Base32 字符串解码为 UTF-8 字符串。</summary>
    public static string DecodeToString(string base32)
        => System.Text.Encoding.UTF8.GetString(Decode(base32));
}
