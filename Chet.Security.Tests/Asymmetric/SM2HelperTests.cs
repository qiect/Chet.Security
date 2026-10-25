using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Asymmetric;

/// <summary>
/// SM2（国密非对称加密算法）单元测试
/// </summary>
public class SM2HelperTests
{
    /// <summary>
    /// 验证生成密钥对返回非空的Base64编码密钥，公钥65字节、私钥32字节
    /// </summary>
    [Fact]
    public void GenerateKeyPair_ReturnsNonEmptyBase64Keys()
    {
        var (pub, priv) = SM2Helper.GenerateKeyPair();
        Assert.False(string.IsNullOrEmpty(pub));
        Assert.False(string.IsNullOrEmpty(priv));
        // Public key: 65 bytes uncompressed point -> 88 base64 chars (no padding).
        Assert.Equal(65, Convert.FromBase64String(pub).Length);
        // Private key: 32 byte scalar -> 44 base64 chars (no padding).
        Assert.Equal(32, Convert.FromBase64String(priv).Length);
    }

    /// <summary>
    /// 验证字符串的SM2加密解密往返一致性
    /// </summary>
    [Fact]
    public void EncryptDecrypt_String_RoundTrips()
    {
        var (pub, priv) = SM2Helper.GenerateKeyPair();
        var plain = "SM2 测试 123";
        var cipher = SM2Helper.Encrypt(plain, pub);
        Assert.Equal(plain, SM2Helper.Decrypt(cipher, priv));
    }

    /// <summary>
    /// 验证Unicode字符（含emoji）的SM2加密解密往返一致性
    /// </summary>
    [Fact]
    public void EncryptDecrypt_Unicode_RoundTrips()
    {
        var (pub, priv) = SM2Helper.GenerateKeyPair();
        var plain = "测试 Test 123 🔒";
        var cipher = SM2Helper.Encrypt(plain, pub);
        Assert.Equal(plain, SM2Helper.Decrypt(cipher, priv));
    }

    /// <summary>
    /// 验证SM2签名和验签流程的正确性
    /// </summary>
    [Fact]
    public void Sign_Verify_Succeeds()
    {
        var (pub, priv) = SM2Helper.GenerateKeyPair();
        var data = "sign this 测试";
        var signature = SM2Helper.Sign(data, priv);
        Assert.True(SM2Helper.Verify(data, signature, pub));
    }

    /// <summary>
    /// 验证对篡改数据进行SM2验签时返回失败
    /// </summary>
    [Fact]
    public void Verify_TamperedData_ReturnsFalse()
    {
        var (pub, priv) = SM2Helper.GenerateKeyPair();
        var signature = SM2Helper.Sign("original-data", priv);
        Assert.False(SM2Helper.Verify("tampered-data", signature, pub));
    }

    /// <summary>
    /// 验证SM2加密结果与明文不同
    /// </summary>
    [Fact]
    public void Encrypt_DiffersFromPlaintext()
    {
        var (pub, _) = SM2Helper.GenerateKeyPair();
        var cipher = SM2Helper.Encrypt("data", pub);
        Assert.NotEqual("data", cipher);
    }

    /// <summary>
    /// 验证对空或null明文进行SM2加密时抛出异常
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Encrypt_NullOrEmptyPlain_Throws(string? plain)
    {
        Assert.ThrowsAny<ArgumentException>(() => SM2Helper.Encrypt(plain!, "public-key"));
    }
}