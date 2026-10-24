using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Chet.Security;

/// <summary>
/// HKDF-SHA256 密钥派生工具类（基于 BouncyCastle），实现 RFC 5869 中的 Extract-Then-Expand 流程。
/// </summary>
public static class HKDFHelper
{
    /// <summary>默认派生长度（字节）。</summary>
    public const int DefaultDerivedLength = 32;

    /// <summary>使用 HKDF-SHA256 从输入密钥材料派生指定长度的字节数组。</summary>
    /// <param name="ikm">输入密钥材料（IKM）字节数组。</param>
    /// <param name="salt">盐值字节数组；可为 null，将按 RFC 5869 用 HashLen 长度的零字节替代。</param>
    /// <param name="info">上下文信息字节数组；可为 null。</param>
    /// <param name="derivedLength">派生长度（字节），默认 32。</param>
    /// <returns>派生出的密钥字节数组。</returns>
    public static byte[] DeriveKey(byte[] ikm, byte[] salt, byte[] info, int derivedLength = DefaultDerivedLength)
    {
        if (ikm is null) throw new ArgumentNullException(nameof(ikm));
        if (derivedLength <= 0) throw new ArgumentOutOfRangeException(nameof(derivedLength), "derivedLength must be positive.");

        var gen = new HkdfBytesGenerator(new Sha256Digest());
        gen.Init(new HkdfParameters(ikm, salt, info));
        var output = new byte[derivedLength];
        gen.GenerateBytes(output, 0, derivedLength);
        return output;
    }

    /// <summary>使用 HKDF-SHA256 派生（输入密钥材料、盐、信息均以 UTF-8 字符串形式给出）。</summary>
    public static byte[] DeriveKey(string ikm, string salt, string info, int derivedLength = DefaultDerivedLength)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(ikm, nameof(ikm));
        CryptoPolyfill.ThrowIfNullOrEmpty(salt, nameof(salt));
        CryptoPolyfill.ThrowIfNullOrEmpty(info, nameof(info));
        return DeriveKey(Encoding.UTF8.GetBytes(ikm),
                         Encoding.UTF8.GetBytes(salt),
                         Encoding.UTF8.GetBytes(info),
                         derivedLength);
    }

    /// <summary>使用 HKDF-SHA256 派生并以 Base64 字符串返回。</summary>
    public static string DeriveKeyBase64(string ikm, string salt, string info, int derivedLength = DefaultDerivedLength)
        => Convert.ToBase64String(DeriveKey(ikm, salt, info, derivedLength));

    /// <summary>使用 HKDF-SHA256 派生并以小写十六进制字符串返回。</summary>
    public static string DeriveKeyHex(string ikm, string salt, string info, int derivedLength = DefaultDerivedLength)
        => CryptoPolyfill.ToHexLower(DeriveKey(ikm, salt, info, derivedLength));
}
