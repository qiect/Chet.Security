namespace Chet.Security;

/// <summary>
/// 加密服务接口，提供统一的加解密门面，由 <see cref="SecurityService"/> 按算法分发到各 *Helper 类。
/// </summary>
public interface ISecurityService
{
    /// <summary>当前算法。</summary>
    CryptoAlgorithm Algorithm { get; }

    /// <summary>编码/加密：对明文进行单向哈希或可逆加密，返回字符串（哈希返回十六进制，加密返回 Base64）。</summary>
    string Encode(string content);

    /// <summary>解码/解密：将密文/编码还原为明文。单向哈希算法不支持解密，将抛出 <see cref="NotSupportedException"/>。</summary>
    string Decode(string content);
}
