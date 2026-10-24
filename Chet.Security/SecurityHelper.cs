namespace Chet.Security;

/// <summary>加解密共享辅助方法：密钥规范化、随机数生成、字节与字符串转换等。</summary>
public static class SecurityHelper
{
    /// <summary>将用户提供的任意长度密钥规范化为算法要求的固定长度字节数组。</summary>
    /// <param name="key">原始密钥（任意长度）。</param>
    /// <param name="mode">规范化模式，默认 <see cref="KeyNormalizeMode.Hash"/>。</param>
    /// <param name="bitLength">目标密钥长度（位），通常为 128/192/256。</param>
    /// <returns>规范化后的密钥字节数组。</returns>
    public static byte[] NormalizeKey(string? key, KeyNormalizeMode mode = KeyNormalizeMode.Hash, int bitLength = 128)
    {
        if (bitLength <= 0 || bitLength % 8 != 0)
            throw new ArgumentException("bitLength must be a positive multiple of 8.", nameof(bitLength));

        int byteLen = bitLength / 8;
        var result = new byte[byteLen];

        if (string.IsNullOrEmpty(key))
            return result;

        byte[] source;
        if (mode == KeyNormalizeMode.Hash)
        {
            // 用 SHA-256 对密钥做哈希后取前 N 字节，保证任意长度输入都能得到稳定且长度足够的密钥材料。
            using var sha = SHA256.Create();
            source = sha.ComputeHash(Encoding.UTF8.GetBytes(key!));
            if (source.Length < byteLen)
            {
                // 不足位时再补一轮哈希拼接。
                var combined = source;
                while (combined.Length < byteLen)
                {
                    var next = sha.ComputeHash(combined);
                    var temp = new byte[combined.Length + next.Length];
                    Buffer.BlockCopy(combined, 0, temp, 0, combined.Length);
                    Buffer.BlockCopy(next, 0, temp, combined.Length, next.Length);
                    combined = temp;
                }
                source = combined;
            }
        }
        else
        {
            source = Encoding.UTF8.GetBytes(key!);
        }

        int start = 0;
        int count = Math.Min(source.Length, byteLen);

        if (source.Length < byteLen && mode == KeyNormalizeMode.PadLeftZero)
            start = byteLen - source.Length;

        Buffer.BlockCopy(source, 0, result, start, count);
        return result;
    }

    /// <summary>生成密码学安全的随机字节数组。</summary>
    /// <param name="length">字节数。</param>
    public static byte[] GenerateRandomBytes(int length)
    {
        if (length < 0) throw new ArgumentOutOfRangeException(nameof(length));
        var bytes = new byte[length];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return bytes;
    }

    /// <summary>生成密码学安全的随机十六进制字符串。</summary>
    /// <param name="length">字节数（输出字符串长度为 length*2）。</param>
    public static string GenerateRandomHex(int length) => CryptoPolyfill.ToHexLower(GenerateRandomBytes(length));

    /// <summary>生成密码学安全的随机 Base64 字符串。</summary>
    public static string GenerateRandomBase64(int length) => Convert.ToBase64String(GenerateRandomBytes(length));

    /// <summary>按指定输出格式将字节数组转为字符串。</summary>
    public static string FormatOutput(byte[] data, OutputFormat format)
        => format switch
        {
            OutputFormat.Base64 => Convert.ToBase64String(data),
            OutputFormat.Hex => CryptoPolyfill.ToHexLower(data),
            OutputFormat.Raw => throw new NotSupportedException("Raw bytes cannot be represented as a string."),
            _ => throw new ArgumentOutOfRangeException(nameof(format)),
        };

    /// <summary>按指定输入格式将字符串转为字节数组。Base64 与 Hex 自动识别失败时回退到 UTF-8。</summary>
    public static byte[] ParseInput(string input, OutputFormat format)
    {
        return format switch
        {
            OutputFormat.Base64 => Convert.FromBase64String(input),
            OutputFormat.Hex => CryptoPolyfill.FromHex(input),
            _ => Encoding.UTF8.GetBytes(input),
        };
    }
}
