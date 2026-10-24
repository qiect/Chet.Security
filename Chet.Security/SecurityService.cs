namespace Chet.Security;

/// <summary>
/// 加密服务实现，按 <see cref="CryptoAlgorithm"/> 分发到各 *Helper 类。
/// </summary>
/// <remarks>
/// 构造参数语义随算法不同：
/// <list type="bullet">
/// <item><see cref="CryptoAlgorithm.AES"/> / <see cref="CryptoAlgorithm.SM4"/>：<paramref name="key"/> 为密钥，<paramref name="iv"/> 为向量（必需）。</item>
/// <item><see cref="CryptoAlgorithm.DES"/> / <see cref="CryptoAlgorithm.TripleDES"/>：<paramref name="key"/> 为密钥。</item>
/// <item><see cref="CryptoAlgorithm.RSA"/> / <see cref="CryptoAlgorithm.SM2"/>：<paramref name="key"/> 为公钥（用于加密），<paramref name="key2"/> 为私钥（用于解密）。</item>
/// <item><see cref="CryptoAlgorithm.MD5"/> / <see cref="CryptoAlgorithm.SHA256"/> / <see cref="CryptoAlgorithm.SHA512"/> / <see cref="CryptoAlgorithm.SM3"/>：<paramref name="key"/> 被忽略，仅 <see cref="Encode"/> 可用。</item>
/// <item><see cref="CryptoAlgorithm.Base64"/>：<paramref name="key"/> 被忽略。</item>
/// </list>
/// </remarks>
public class SecurityService : ISecurityService
{
    /// <summary>当前算法。</summary>
    public CryptoAlgorithm Algorithm { get; }

    /// <summary>主密钥（对称密钥 / 公钥）。</summary>
    public string Key { get; }

    /// <summary>辅助密钥（私钥）。</summary>
    public string? Key2 { get; }

    /// <summary>初始化向量（对称加密的 IV）。</summary>
    public string? Iv { get; }

    /// <summary>实例化加密服务。</summary>
    /// <param name="algorithm">算法。</param>
    /// <param name="key">主密钥（对称密钥或公钥）。</param>
    /// <param name="key2">辅助密钥（私钥），RSA/SM2 解密时必需。</param>
    /// <param name="iv">初始化向量，AES/SM4 必需。</param>
    public SecurityService(CryptoAlgorithm algorithm, string key, string? key2 = null, string? iv = null)
    {
        Algorithm = algorithm;
        Key = key ?? string.Empty;
        Key2 = key2;
        Iv = iv;
    }

    /// <summary>编码/加密。</summary>
    public string Encode(string content)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(content, nameof(content));
        return Algorithm switch
        {
            CryptoAlgorithm.MD5 => MD5Helper.ComputeHash(content),
            CryptoAlgorithm.SHA256 => SHAHelper.ComputeSHA256(content),
            CryptoAlgorithm.SHA512 => SHAHelper.ComputeSHA512(content),
            CryptoAlgorithm.SM3 => SM3Helper.ComputeHash(content),
            CryptoAlgorithm.AES => AESHelper.Encrypt(content, Key, Iv ?? Key),
            CryptoAlgorithm.DES => DESHelper.Encrypt(content, Key),
            CryptoAlgorithm.TripleDES => TripleDESHelper.Encrypt(content, Key),
            CryptoAlgorithm.SM4 => SM4Helper.Encrypt(content, Key, Iv ?? Key),
            CryptoAlgorithm.RSA => RSAHelper.Encrypt(content, Key),
            CryptoAlgorithm.SM2 => SM2Helper.Encrypt(content, Key),
            CryptoAlgorithm.Base64 => Base64Helper.EncodeString(content),
            _ => throw new NotSupportedException($"Unsupported algorithm: {Algorithm}"),
        };
    }

    /// <summary>解码/解密。</summary>
    public string Decode(string content)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(content, nameof(content));
        return Algorithm switch
        {
            CryptoAlgorithm.MD5 or CryptoAlgorithm.SHA256 or CryptoAlgorithm.SHA512 or CryptoAlgorithm.SM3
                => throw new NotSupportedException($"{Algorithm} 是单向哈希算法，不支持解密。"),
            CryptoAlgorithm.AES => AESHelper.Decrypt(content, Key, Iv ?? Key),
            CryptoAlgorithm.DES => DESHelper.Decrypt(content, Key),
            CryptoAlgorithm.TripleDES => TripleDESHelper.Decrypt(content, Key),
            CryptoAlgorithm.SM4 => SM4Helper.Decrypt(content, Key, Iv ?? Key),
            CryptoAlgorithm.RSA => RSAHelper.Decrypt(content, Key2 ?? throw new ArgumentException("RSA 解密需要私钥 (key2)。", nameof(Key2))),
            CryptoAlgorithm.SM2 => SM2Helper.Decrypt(content, Key2 ?? throw new ArgumentException("SM2 解密需要私钥 (key2)。", nameof(Key2))),
            CryptoAlgorithm.Base64 => Base64Helper.DecodeToString(content),
            _ => throw new NotSupportedException($"Unsupported algorithm: {Algorithm}"),
        };
    }
}
