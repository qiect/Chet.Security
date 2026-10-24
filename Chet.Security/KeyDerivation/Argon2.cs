using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Chet.Security;

/// <summary>
/// Argon2id 密钥派生工具类（基于 BouncyCastle），适用于密码哈希等需要 GPU/ASIC 抗性的场景。
/// </summary>
public static class Argon2Helper
{
    /// <summary>默认迭代次数。</summary>
    public const int DefaultIterations = 3;

    /// <summary>默认内存开销（KB）。</summary>
    public const int DefaultMemoryKb = 65536;

    /// <summary>默认并行参数。</summary>
    public const int DefaultParallelism = 1;

    /// <summary>默认派生长度（字节）。</summary>
    public const int DefaultDerivedLength = 32;

    /// <summary>使用 Argon2id 从密码派生指定长度的字节数组。</summary>
    /// <param name="password">密码字节数组。</param>
    /// <param name="salt">盐值字节数组。</param>
    /// <param name="iterations">迭代次数，默认 3。</param>
    /// <param name="memoryKb">内存开销（KB），默认 65536。</param>
    /// <param name="parallelism">并行参数，默认 1。</param>
    /// <param name="derivedLength">派生长度（字节），默认 32。</param>
    /// <returns>派生出的密钥字节数组。</returns>
    public static byte[] DeriveBytes(byte[] password, byte[] salt, int iterations = DefaultIterations, int memoryKb = DefaultMemoryKb, int parallelism = DefaultParallelism, int derivedLength = DefaultDerivedLength)
    {
        if (password is null) throw new ArgumentNullException(nameof(password));
        if (salt is null) throw new ArgumentNullException(nameof(salt));
        if (iterations <= 0) throw new ArgumentOutOfRangeException(nameof(iterations), "iterations must be positive.");
        if (memoryKb <= 0) throw new ArgumentOutOfRangeException(nameof(memoryKb), "memoryKb must be positive.");
        if (parallelism <= 0) throw new ArgumentOutOfRangeException(nameof(parallelism), "parallelism must be positive.");
        if (derivedLength <= 0) throw new ArgumentOutOfRangeException(nameof(derivedLength), "derivedLength must be positive.");

        var gen = new Argon2BytesGenerator();
        var parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
            .WithSalt(salt)
            .WithIterations(iterations)
            .WithMemoryAsKB(memoryKb)
            .WithParallelism(parallelism)
            .Build();
        gen.Init(parameters);

        var output = new byte[derivedLength];
        gen.GenerateBytes(password, output, 0, derivedLength);
        return output;
    }

    /// <summary>使用 Argon2id 从密码派生指定长度的字节数组（密码与盐均为 UTF-8 字符串）。</summary>
    public static byte[] DeriveBytes(string password, string salt, int iterations = DefaultIterations, int memoryKb = DefaultMemoryKb, int parallelism = DefaultParallelism, int derivedLength = DefaultDerivedLength)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(password, nameof(password));
        CryptoPolyfill.ThrowIfNullOrEmpty(salt, nameof(salt));
        return DeriveBytes(Encoding.UTF8.GetBytes(password), Encoding.UTF8.GetBytes(salt), iterations, memoryKb, parallelism, derivedLength);
    }

    /// <summary>使用 Argon2id 派生并以 Base64 字符串返回。</summary>
    public static string DeriveBase64(string password, string salt, int iterations = DefaultIterations, int memoryKb = DefaultMemoryKb, int parallelism = DefaultParallelism, int derivedLength = DefaultDerivedLength)
        => Convert.ToBase64String(DeriveBytes(password, salt, iterations, memoryKb, parallelism, derivedLength));

    /// <summary>使用 Argon2id 派生并以小写十六进制字符串返回。</summary>
    public static string DeriveHex(string password, string salt, int iterations = DefaultIterations, int memoryKb = DefaultMemoryKb, int parallelism = DefaultParallelism, int derivedLength = DefaultDerivedLength)
        => CryptoPolyfill.ToHexLower(DeriveBytes(password, salt, iterations, memoryKb, parallelism, derivedLength));
}
