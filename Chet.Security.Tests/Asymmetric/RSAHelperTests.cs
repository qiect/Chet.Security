using System.Security.Cryptography;
using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Asymmetric;

/// <summary>
/// RSA（非对称加密算法）单元测试
/// </summary>
public class RSAHelperTests
{
    /// <summary>
    /// 验证生成密钥对返回有效的PEM格式字符串
    /// </summary>
    [Fact]
    public void GenerateKeyPair_ReturnsPemStrings()
    {
        var (pub, priv) = RSAHelper.GenerateKeyPair();
        Assert.StartsWith("-----BEGIN", pub);
        Assert.StartsWith("-----BEGIN", priv);
        Assert.Contains("PUBLIC KEY", pub);
        Assert.Contains("PRIVATE KEY", priv);
    }

    /// <summary>
    /// 验证使用无效密钥大小生成密钥对时抛出异常
    /// </summary>
    [Fact]
    public void GenerateKeyPair_InvalidKeySize_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => RSAHelper.GenerateKeyPair(100));
    }

    /// <summary>
    /// 验证字符串的加密解密往返一致性
    /// </summary>
    [Fact]
    public void EncryptDecrypt_String_RoundTrips()
    {
        var (pub, priv) = RSAHelper.GenerateKeyPair();
        var plain = "RSA 测试 123";
        var cipher = RSAHelper.Encrypt(plain, pub);
        Assert.Equal(plain, RSAHelper.Decrypt(cipher, priv));
    }

    /// <summary>
    /// 验证Unicode字符（含emoji）的加密解密往返一致性
    /// </summary>
    [Fact]
    public void EncryptDecrypt_Unicode_RoundTrips()
    {
        var (pub, priv) = RSAHelper.GenerateKeyPair();
        var plain = "测试 Test 123 🔒";
        var cipher = RSAHelper.Encrypt(plain, pub);
        Assert.Equal(plain, RSAHelper.Decrypt(cipher, priv));
    }

    /// <summary>
    /// 验证长文本的EncryptLong/DecryptLong分块加密解密往返一致性
    /// </summary>
    [Fact]
    public void EncryptLong_DecryptLong_RoundTripsOnLongText()
    {
        var (pub, priv) = RSAHelper.GenerateKeyPair();
        var plain = new string('A', 500) + "测试 tail";
#pragma warning disable CS0618
        var cipher = RSAHelper.EncryptLong(plain, pub);
        Assert.Equal(plain, RSAHelper.DecryptLong(cipher, priv));
#pragma warning restore CS0618
    }

    /// <summary>
    /// 验证长文本的EncryptChunked/DecryptChunked并行分块加密解密往返一致性
    /// </summary>
    [Fact]
    public void EncryptChunked_DecryptChunked_RoundTripsOnLongText()
    {
        var (pub, priv) = RSAHelper.GenerateKeyPair();
        var plain = new string('A', 500) + "分块测试 tail 🔒";
        var cipher = RSAHelper.EncryptChunked(plain, pub);
        Assert.Equal(plain, RSAHelper.DecryptChunked(cipher, priv));
    }

    /// <summary>
    /// 验证EncryptChunked使用点号分隔符
    /// </summary>
    [Fact]
    public void EncryptChunked_UsesDotSeparator()
    {
        var (pub, _) = RSAHelper.GenerateKeyPair();
        var plain = new string('X', 500);
        var cipher = RSAHelper.EncryptChunked(plain, pub);
        Assert.Contains(".", cipher);
        Assert.DoesNotContain("|||", cipher);
    }

    /// <summary>
    /// 验证RSA签名和验签流程的正确性
    /// </summary>
    [Fact]
    public void SignData_VerifyData_Succeeds()
    {
        var (pub, priv) = RSAHelper.GenerateKeyPair();
        var data = "sign this 测试";
        var signature = RSAHelper.SignData(data, priv);
        Assert.True(RSAHelper.VerifyData(data, signature, pub));
    }

    /// <summary>
    /// 验证对篡改数据进行RSA验签时返回失败
    /// </summary>
    [Fact]
    public void VerifyData_TamperedData_ReturnsFalse()
    {
        var (pub, priv) = RSAHelper.GenerateKeyPair();
        var signature = RSAHelper.SignData("original-data", priv);
        Assert.False(RSAHelper.VerifyData("tampered-data", signature, pub));
    }

    /// <summary>
    /// 验证使用私钥PEM作为公钥进行加密时抛出异常
    /// </summary>
    [Fact]
    public void Encrypt_WithPrivateKeyPemAsPublic_Throws()
    {
        var (pub, priv) = RSAHelper.GenerateKeyPair();
        Assert.ThrowsAny<CryptographicException>(() => RSAHelper.Encrypt("data", priv));
    }

    /// <summary>
    /// 验证对空或null明文进行加密时抛出异常
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Encrypt_NullOrEmptyPlain_Throws(string? plain)
    {
        Assert.ThrowsAny<ArgumentException>(() => RSAHelper.Encrypt(plain!, "public-key-pem"));
    }
}