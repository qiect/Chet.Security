using Org.BouncyCastle.Crypto.Generators;

namespace Chet.Security;

/// <summary>
/// SCrypt 密钥派生工具类（基于 BouncyCastle），适用于需要内存困难型 KDF 的场景，如密码哈希与密钥派生。
/// </summary>
public static class SCryptHelper
{
    /// <summary>默认 CPU/内存开销参数 N（必须为 2 的幂）。</summary>
    public const int DefaultN = 1 << 14;

    /// <summary>默认块大小参数 r。</summary>
    public const int DefaultR = 8;

    /// <summary>默认并行参数 p。</summary>
    public const int DefaultP = 1;

    /// <summary>默认派生长度（字节）。</summary>
    public const int DefaultDerivedLength = 32;

    /// <summary>使用 SCrypt 从密码派生指定长度的字节数组。</summary>
    /// <param name="password">密码字节数组。</param>
    /// <param name="salt">盐值字节数组。</param>
    /// <param name="n">CPU/内存开销参数 N，必须为 2 的幂，默认 16384。</param>
    /// <param name="r">块大小参数 r，默认 8。</param>
    /// <param name="p">并行参数 p，默认 1。</param>
    /// <param name="derivedLength">派生长度（字节），默认 32。</param>
    /// <returns>派生出的密钥字节数组。</returns>
    public static byte[] DeriveBytes(byte[] password, byte[] salt, int n = DefaultN, int r = DefaultR, int p = DefaultP, int derivedLength = DefaultDerivedLength)
    {
        if (password is null) throw new ArgumentNullException(nameof(password));
        if (salt is null) throw new ArgumentNullException(nameof(salt));
        if (n <= 0 || (n & (n - 1)) != 0) throw new ArgumentException("N must be a power of two greater than 0.", nameof(n));
        if (r <= 0) throw new ArgumentOutOfRangeException(nameof(r), "r must be positive.");
        if (p <= 0) throw new ArgumentOutOfRangeException(nameof(p), "p must be positive.");
        if (derivedLength <= 0) throw new ArgumentOutOfRangeException(nameof(derivedLength), "derivedLength must be positive.");

        return SCrypt.Generate(password, salt, n, r, p, derivedLength);
    }

    /// <summary>使用 SCrypt 从密码派生指定长度的字节数组（密码与盐均为 UTF-8 字符串）。</summary>
    public static byte[] DeriveBytes(string password, string salt, int n = DefaultN, int r = DefaultR, int p = DefaultP, int derivedLength = DefaultDerivedLength)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(password, nameof(password));
        CryptoPolyfill.ThrowIfNullOrEmpty(salt, nameof(salt));
        return DeriveBytes(Encoding.UTF8.GetBytes(password), Encoding.UTF8.GetBytes(salt), n, r, p, derivedLength);
    }

    /// <summary>使用 SCrypt 派生并以 Base64 字符串返回。</summary>
    public static string DeriveBase64(string password, string salt, int n = DefaultN, int r = DefaultR, int p = DefaultP, int derivedLength = DefaultDerivedLength)
        => Convert.ToBase64String(DeriveBytes(password, salt, n, r, p, derivedLength));

    /// <summary>使用 SCrypt 派生并以小写十六进制字符串返回。</summary>
    public static string DeriveHex(string password, string salt, int n = DefaultN, int r = DefaultR, int p = DefaultP, int derivedLength = DefaultDerivedLength)
        => CryptoPolyfill.ToHexLower(DeriveBytes(password, salt, n, r, p, derivedLength));
}
