namespace Chet.Security;

/// <summary>
/// 密码学安全的随机数生成助手类，基于 <see cref="RandomNumberGenerator"/>，提供字节、整数、长整数、
/// 浮点数、十六进制/Base64 字符串、口令与 UUID 等常用生成方法。
/// </summary>
public static class SecureRandomHelper
{
    /// <summary>小写字母码表。</summary>
    public const string AlphabetLower = "abcdefghijklmnopqrstuvwxyz";
    /// <summary>大写字母码表。</summary>
    public const string AlphabetUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    /// <summary>数字码表。</summary>
    public const string Digits = "0123456789";
    /// <summary>符号码表。</summary>
    public const string Symbols = "!@#$%^&*()-_=+[]{};:,.?/";

    /// <summary>生成密码学安全的随机字节数组。</summary>
    /// <param name="length">字节数，必须大于等于 0。</param>
    /// <returns>随机字节数组。</returns>
    public static byte[] GenerateBytes(int length)
    {
        if (length < 0) throw new ArgumentOutOfRangeException(nameof(length), "length must be non-negative.");
        var buffer = new byte[length];
        RandomNumberGenerator.Fill(buffer);
        return buffer;
    }

    /// <summary>生成密码学安全的随机 <see cref="int"/>（覆盖 int32 全域）。</summary>
    public static int GenerateInt()
    {
        var buffer = new byte[4];
        RandomNumberGenerator.Fill(buffer);
        return BitConverter.ToInt32(buffer, 0);
    }

    /// <summary>生成密码学安全的指定范围内的随机整数（不含上界，使用拒绝采样消除模取偏）。</summary>
    /// <param name="minInclusive">下界（含）。</param>
    /// <param name="maxExclusive">上界（不含）。</param>
    /// <returns>位于 [minInclusive, maxExclusive) 区间的随机整数。</returns>
    public static int GenerateInt(int minInclusive, int maxExclusive)
    {
        if (maxExclusive <= minInclusive)
            throw new ArgumentOutOfRangeException(nameof(maxExclusive), "maxExclusive must be greater than minInclusive.");

        ulong range = (ulong)(maxExclusive - minInclusive);
        ulong threshold = (1UL << 32) - ((1UL << 32) % range);
        var buffer = new byte[4];
        for (;;)
        {
            RandomNumberGenerator.Fill(buffer);
            ulong v = BitConverter.ToUInt32(buffer, 0);
            if (v < threshold)
                return minInclusive + (int)(v % range);
        }
    }

    /// <summary>生成密码学安全的随机 <see cref="long"/>（覆盖 int64 全域）。</summary>
    public static long GenerateLong()
    {
        var buffer = new byte[8];
        RandomNumberGenerator.Fill(buffer);
        return BitConverter.ToInt64(buffer, 0);
    }

    /// <summary>生成密码学安全的随机 <see cref="double"/>，区间为 [0, 1)。</summary>
    public static double GenerateDouble()
    {
        var buffer = new byte[8];
        RandomNumberGenerator.Fill(buffer);
        ulong v = BitConverter.ToUInt64(buffer, 0);
        // 取高 53 位以获得完整双精度尾数，再除以 2^53。
        return (v >> 11) * (1.0 / (1UL << 53));
    }

    /// <summary>生成密码学安全的随机十六进制字符串。</summary>
    /// <param name="byteLength">字节数（输出字符串长度为 byteLength*2）。</param>
    public static string GenerateHex(int byteLength) => CryptoPolyfill.ToHexLower(GenerateBytes(byteLength));

    /// <summary>生成密码学安全的随机 Base64 字符串。</summary>
    /// <param name="byteLength">字节数。</param>
    public static string GenerateBase64(int byteLength) => Convert.ToBase64String(GenerateBytes(byteLength));

    /// <summary>生成密码学安全的随机口令。</summary>
    /// <param name="length">口令长度，默认 16。</param>
    /// <param name="includeSymbols">是否包含符号字符，默认 true。</param>
    /// <returns>随机口令字符串。</returns>
    public static string GeneratePassword(int length = 16, bool includeSymbols = true)
    {
        if (length <= 0) throw new ArgumentOutOfRangeException(nameof(length), "length must be positive.");

        var alphabet = AlphabetLower + AlphabetUpper + Digits;
        if (includeSymbols) alphabet += Symbols;

        var result = new char[length];
        for (int i = 0; i < length; i++)
            result[i] = alphabet[GenerateInt(0, alphabet.Length)];
        return new string(result);
    }

    /// <summary>生成 GUID 字符串（带连字符的标准 D 格式）。</summary>
    public static string GenerateUuid() => Guid.NewGuid().ToString();

    /// <summary>用密码学安全的随机数据填充给定缓冲区。</summary>
    /// <param name="buffer">待填充缓冲区。</param>
    public static void Fill(byte[] buffer)
    {
        if (buffer is null) throw new ArgumentNullException(nameof(buffer));
        RandomNumberGenerator.Fill(buffer);
    }
}
