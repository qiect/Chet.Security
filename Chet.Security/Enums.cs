namespace Chet.Security;

/// <summary>密钥补全模式，用于将用户提供的任意长度密钥规范化为算法要求的长度。</summary>
public enum KeyNormalizeMode
{
    /// <summary>对密钥做哈希后截取/补齐到目标长度（推荐，可处理任意长度输入）。</summary>
    Hash,
    /// <summary>右侧补零到目标长度。</summary>
    PadRightZero,
    /// <summary>左侧补零到目标长度。</summary>
    PadLeftZero,
}

/// <summary>输出格式：明文/密文/哈希值的字符串表示形式。</summary>
public enum OutputFormat
{
    /// <summary>Base64 字符串。</summary>
    Base64,
    /// <summary>小写十六进制字符串。</summary>
    Hex,
    /// <summary>原始字节数组。</summary>
    Raw,
}

/// <summary>统一加密算法标识，供 <see cref="ISecurityService"/> 门面分发使用。</summary>
public enum CryptoAlgorithm : int
{
    /// <summary>MD5 摘要（不可逆）。</summary>
    MD5 = 1,
    /// <summary>SHA-256 摘要（不可逆）。</summary>
    SHA256 = 2,
    /// <summary>SHA-512 摘要（不可逆）。</summary>
    SHA512 = 3,
    /// <summary>SM3 国密摘要（不可逆）。</summary>
    SM3 = 4,
    /// <summary>AES 对称加密。</summary>
    AES = 5,
    /// <summary>DES 对称加密（已不安全，仅做兼容）。</summary>
    DES = 6,
    /// <summary>TripleDES（3DES）对称加密。</summary>
    TripleDES = 7,
    /// <summary>SM4 国密对称加密。</summary>
    SM4 = 8,
    /// <summary>RSA 非对称加密。</summary>
    RSA = 9,
    /// <summary>SM2 国密非对称加密。</summary>
    SM2 = 10,
    /// <summary>Base64 编码（可逆，非加密）。</summary>
    Base64 = 11,
}
