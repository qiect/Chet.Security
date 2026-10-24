namespace Chet.Security;

/// <summary>
/// 密码哈希助手类。注意：本类并非原生 BCrypt 实现，而是基于 PBKDF2-HMAC-SHA256 的密码哈希封装，
/// 提供与 BCrypt 兼容的 API 形态，避免引入额外的 NuGet 依赖。
/// 输出格式：<c>pbkdf2$iterations$saltBase64$hashBase64</c>。
/// </summary>
public static class BCryptHelper
{
    /// <summary>格式前缀，用于标识由本类生成的密码哈希字符串。</summary>
    public const string Prefix = "pbkdf2";

    /// <summary>默认迭代次数。</summary>
    public const int DefaultIterations = 100000;

    /// <summary>默认派生哈希长度（字节）。</summary>
    public const int DefaultHashLength = 32;

    /// <summary>默认盐值长度（字节）。</summary>
    public const int DefaultSaltLength = 16;

    /// <summary>使用 PBKDF2-HMAC-SHA256 哈希密码，返回 <c>pbkdf2$iterations$saltBase64$hashBase64</c> 格式字符串。</summary>
    /// <param name="password">原始密码。</param>
    /// <param name="iterations">迭代次数，默认 100000。</param>
    /// <returns>包含算法、迭代次数、盐与哈希值的格式化字符串。</returns>
    public static string HashPassword(string password, int iterations = DefaultIterations)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(password, nameof(password));
        if (iterations <= 0) throw new ArgumentOutOfRangeException(nameof(iterations), "iterations must be positive.");

        var salt = SecurityHelper.GenerateRandomBytes(DefaultSaltLength);
        using var derive = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256);
        var hash = derive.GetBytes(DefaultHashLength);
        return $"{Prefix}${iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    /// <summary>校验密码是否与已存储的哈希字符串匹配（恒定时间比较）。</summary>
    /// <param name="password">待校验密码。</param>
    /// <param name="stored">已存储的 <c>pbkdf2$...</c> 格式哈希字符串。</param>
    /// <returns>匹配返回 true；否则返回 false。</returns>
    public static bool VerifyPassword(string password, string stored)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(password, nameof(password));
        CryptoPolyfill.ThrowIfNullOrEmpty(stored, nameof(stored));

        var parts = stored.Split('$');
        if (parts.Length != 4 || parts[0] != Prefix) return false;
        if (!int.TryParse(parts[1], out var iterations) || iterations <= 0) return false;

        byte[] salt, expected;
        try
        {
            salt = Convert.FromBase64String(parts[2]);
            expected = Convert.FromBase64String(parts[3]);
        }
        catch (FormatException)
        {
            return false;
        }

        using var derive = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256);
        var actual = derive.GetBytes(expected.Length);
        return ConstantTimeEquals(actual, expected);
    }

    /// <summary>对两个字节数组进行恒定时间相等比较。</summary>
    private static bool ConstantTimeEquals(byte[] a, byte[] b)
    {
        if (a is null || b is null) return false;
        if (a.Length != b.Length) return false;
        int diff = 0;
        for (int i = 0; i < a.Length; i++)
            diff |= a[i] ^ b[i];
        return diff == 0;
    }
}
