using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Chet.Security;

/// <summary>
/// SHA 系列摘要工具类，提供 SHA-1/SHA-256/SHA-384/SHA-512 及 SHA-3(256/384/512) 摘要计算。
/// SHA-1/256/384/512 使用 BCL 的 <see cref="SHA1"/>/<see cref="SHA256"/> 等实现；
/// SHA-3 在两个目标框架下均使用 BouncyCastle 的 <see cref="Sha3Digest"/> 实现，以规避 net8 SHA3 的平台限制并保持行为一致。
/// </summary>
public static class SHAHelper
{
    /// <summary>计算字节数组的 SHA-1 摘要，返回小写十六进制字符串。</summary>
    /// <param name="data">待计算的字节数据。</param>
    /// <returns>40 字符长度的小写十六进制摘要。</returns>
    public static string ComputeSHA1(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        using var alg = SHA1.Create();
        return CryptoPolyfill.ToHexLower(Compute(data, alg));
    }

    /// <summary>将字符串按 UTF-8 编码后计算 SHA-1 摘要，返回小写十六进制字符串。</summary>
    /// <param name="text">待计算的字符串。</param>
    /// <returns>40 字符长度的小写十六进制摘要。</returns>
    public static string ComputeSHA1(string text)
    {
        CryptoPolyfill.ThrowIfNull(text, nameof(text));
        return ComputeSHA1(Encoding.UTF8.GetBytes(text));
    }

    /// <summary>计算字节数组的 SHA-256 摘要，返回小写十六进制字符串。</summary>
    /// <param name="data">待计算的字节数据。</param>
    /// <returns>64 字符长度的小写十六进制摘要。</returns>
    public static string ComputeSHA256(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        using var alg = SHA256.Create();
        return CryptoPolyfill.ToHexLower(Compute(data, alg));
    }

    /// <summary>将字符串按 UTF-8 编码后计算 SHA-256 摘要，返回小写十六进制字符串。</summary>
    /// <param name="text">待计算的字符串。</param>
    /// <returns>64 字符长度的小写十六进制摘要。</returns>
    public static string ComputeSHA256(string text)
    {
        CryptoPolyfill.ThrowIfNull(text, nameof(text));
        return ComputeSHA256(Encoding.UTF8.GetBytes(text));
    }

    /// <summary>计算字节数组的 SHA-384 摘要，返回小写十六进制字符串。</summary>
    /// <param name="data">待计算的字节数据。</param>
    /// <returns>96 字符长度的小写十六进制摘要。</returns>
    public static string ComputeSHA384(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        using var alg = SHA384.Create();
        return CryptoPolyfill.ToHexLower(Compute(data, alg));
    }

    /// <summary>将字符串按 UTF-8 编码后计算 SHA-384 摘要，返回小写十六进制字符串。</summary>
    /// <param name="text">待计算的字符串。</param>
    /// <returns>96 字符长度的小写十六进制摘要。</returns>
    public static string ComputeSHA384(string text)
    {
        CryptoPolyfill.ThrowIfNull(text, nameof(text));
        return ComputeSHA384(Encoding.UTF8.GetBytes(text));
    }

    /// <summary>计算字节数组的 SHA-512 摘要，返回小写十六进制字符串。</summary>
    /// <param name="data">待计算的字节数据。</param>
    /// <returns>128 字符长度的小写十六进制摘要。</returns>
    public static string ComputeSHA512(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        using var alg = SHA512.Create();
        return CryptoPolyfill.ToHexLower(Compute(data, alg));
    }

    /// <summary>将字符串按 UTF-8 编码后计算 SHA-512 摘要，返回小写十六进制字符串。</summary>
    /// <param name="text">待计算的字符串。</param>
    /// <returns>128 字符长度的小写十六进制摘要。</returns>
    public static string ComputeSHA512(string text)
    {
        CryptoPolyfill.ThrowIfNull(text, nameof(text));
        return ComputeSHA512(Encoding.UTF8.GetBytes(text));
    }

    /// <summary>计算字节数组的 SHA3-256 摘要（BouncyCastle 实现），返回小写十六进制字符串。</summary>
    /// <param name="data">待计算的字节数据。</param>
    /// <returns>64 字符长度的小写十六进制摘要。</returns>
    public static string ComputeSHA3_256(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        return CryptoPolyfill.ToHexLower(ComputeBC(data, new Sha3Digest(256)));
    }

    /// <summary>将字符串按 UTF-8 编码后计算 SHA3-256 摘要，返回小写十六进制字符串。</summary>
    /// <param name="text">待计算的字符串。</param>
    /// <returns>64 字符长度的小写十六进制摘要。</returns>
    public static string ComputeSHA3_256(string text)
    {
        CryptoPolyfill.ThrowIfNull(text, nameof(text));
        return ComputeSHA3_256(Encoding.UTF8.GetBytes(text));
    }

    /// <summary>计算字节数组的 SHA3-384 摘要（BouncyCastle 实现），返回小写十六进制字符串。</summary>
    /// <param name="data">待计算的字节数据。</param>
    /// <returns>96 字符长度的小写十六进制摘要。</returns>
    public static string ComputeSHA3_384(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        return CryptoPolyfill.ToHexLower(ComputeBC(data, new Sha3Digest(384)));
    }

    /// <summary>将字符串按 UTF-8 编码后计算 SHA3-384 摘要，返回小写十六进制字符串。</summary>
    /// <param name="text">待计算的字符串。</param>
    /// <returns>96 字符长度的小写十六进制摘要。</returns>
    public static string ComputeSHA3_384(string text)
    {
        CryptoPolyfill.ThrowIfNull(text, nameof(text));
        return ComputeSHA3_384(Encoding.UTF8.GetBytes(text));
    }

    /// <summary>计算字节数组的 SHA3-512 摘要（BouncyCastle 实现），返回小写十六进制字符串。</summary>
    /// <param name="data">待计算的字节数据。</param>
    /// <returns>128 字符长度的小写十六进制摘要。</returns>
    public static string ComputeSHA3_512(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        return CryptoPolyfill.ToHexLower(ComputeBC(data, new Sha3Digest(512)));
    }

    /// <summary>将字符串按 UTF-8 编码后计算 SHA3-512 摘要，返回小写十六进制字符串。</summary>
    /// <param name="text">待计算的字符串。</param>
    /// <returns>128 字符长度的小写十六进制摘要。</returns>
    public static string ComputeSHA3_512(string text)
    {
        CryptoPolyfill.ThrowIfNull(text, nameof(text));
        return ComputeSHA3_512(Encoding.UTF8.GetBytes(text));
    }

    /// <summary>读取文件并计算其 SHA-256 摘要，返回小写十六进制字符串。</summary>
    /// <param name="filePath">文件绝对或相对路径。</param>
    /// <returns>64 字符长度的小写十六进制摘要。</returns>
    /// <exception cref="FileNotFoundException">文件不存在时抛出。</exception>
    public static string ComputeFileSHA256(string filePath)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(filePath, nameof(filePath));
        if (!File.Exists(filePath))
            throw new FileNotFoundException("Specified file was not found.", filePath);
        using var stream = File.OpenRead(filePath);
        using var alg = SHA256.Create();
        return CryptoPolyfill.ToHexLower(alg.ComputeHash(stream));
    }

    /// <summary>使用 BCL <see cref="HashAlgorithm"/> 计算字节数组摘要，返回原始字节数组。</summary>
    /// <param name="data">待计算数据。</param>
    /// <param name="alg">已创建的 <see cref="HashAlgorithm"/> 实例（由调用方负责释放）。</param>
    /// <returns>原始摘要字节数组。</returns>
    private static byte[] Compute(byte[] data, HashAlgorithm alg) => alg.ComputeHash(data);

    /// <summary>使用 BouncyCastle <see cref="IDigest"/> 计算字节数组摘要，返回原始字节数组。</summary>
    /// <param name="data">待计算数据。</param>
    /// <param name="digest">已创建的 <see cref="IDigest"/> 实例。</param>
    /// <returns>长度为 <see cref="IDigest.GetDigestSize"/> 的原始摘要字节数组。</returns>
    private static byte[] ComputeBC(byte[] data, IDigest digest)
    {
        digest.BlockUpdate(data, 0, data.Length);
        var output = new byte[digest.GetDigestSize()];
        digest.DoFinal(output, 0);
        return output;
    }
}
