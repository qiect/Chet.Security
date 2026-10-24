namespace Chet.Security;

/// <summary>
/// PBKDF2-HMAC-SHA256 密钥派生工具类，基于 BCL 的 <see cref="Rfc2898DeriveBytes"/> 实现，可用于密码哈希与密钥派生。
/// </summary>
public static class PBKDF2Helper
{
    /// <summary>默认迭代次数。</summary>
    public const int DefaultIterations = 10000;

    /// <summary>默认派生长度（字节）。</summary>
    public const int DefaultDerivedLength = 32;

    /// <summary>使用 PBKDF2-HMAC-SHA256 从密码派生指定长度的字节数组。</summary>
    /// <param name="password">原始密码。</param>
    /// <param name="salt">盐值字节数组。</param>
    /// <param name="iterations">迭代次数，默认 10000。</param>
    /// <param name="derivedLength">派生长度（字节），默认 32。</param>
    /// <returns>派生出的密钥字节数组。</returns>
    public static byte[] DeriveBytes(string password, byte[] salt, int iterations = DefaultIterations, int derivedLength = DefaultDerivedLength)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(password, nameof(password));
        if (salt is null) throw new ArgumentNullException(nameof(salt));
        if (iterations <= 0) throw new ArgumentOutOfRangeException(nameof(iterations), "iterations must be positive.");
        if (derivedLength <= 0) throw new ArgumentOutOfRangeException(nameof(derivedLength), "derivedLength must be positive.");

        var passwordBytes = Encoding.UTF8.GetBytes(password);
        using var derive = new Rfc2898DeriveBytes(passwordBytes, salt, iterations, HashAlgorithmName.SHA256);
        return derive.GetBytes(derivedLength);
    }

    /// <summary>使用 PBKDF2-HMAC-SHA256 从密码派生指定长度的字节数组（盐以 UTF-8 字符串形式给出）。</summary>
    public static byte[] DeriveBytes(string password, string salt, int iterations = DefaultIterations, int derivedLength = DefaultDerivedLength)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(password, nameof(password));
        CryptoPolyfill.ThrowIfNullOrEmpty(salt, nameof(salt));
        return DeriveBytes(password, Encoding.UTF8.GetBytes(salt), iterations, derivedLength);
    }

    /// <summary>使用 PBKDF2-HMAC-SHA256 派生并以 Base64 字符串返回。</summary>
    public static string DeriveBase64(string password, string salt, int iterations = DefaultIterations, int derivedLength = DefaultDerivedLength)
        => Convert.ToBase64String(DeriveBytes(password, salt, iterations, derivedLength));

    /// <summary>使用 PBKDF2-HMAC-SHA256 派生并以小写十六进制字符串返回。</summary>
    public static string DeriveHex(string password, string salt, int iterations = DefaultIterations, int derivedLength = DefaultDerivedLength)
        => CryptoPolyfill.ToHexLower(DeriveBytes(password, salt, iterations, derivedLength));

    /// <summary>生成密码学安全的随机盐值。</summary>
    /// <param name="length">盐值长度（字节），默认 16。</param>
    /// <returns>随机盐值字节数组。</returns>
    public static byte[] GenerateSalt(int length = 16)
    {
        if (length <= 0) throw new ArgumentOutOfRangeException(nameof(length), "length must be positive.");
        return SecurityHelper.GenerateRandomBytes(length);
    }
}
