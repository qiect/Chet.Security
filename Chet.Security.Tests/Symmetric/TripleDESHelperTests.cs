using System.Security.Cryptography;
using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Symmetric;

/// <summary>
/// TripleDES（3DES）对称加密算法单元测试
/// </summary>
public class TripleDESHelperTests
{
    /// <summary>
    /// 验证字符串的TripleDES加密解密往返一致性
    /// </summary>
    [Fact]
    public void EncryptDecrypt_String_RoundTrips()
    {
        var plain = "测试 Test 123 🔒";
        var cipher = TripleDESHelper.Encrypt(plain, "my-secret-key");
        Assert.Equal(plain, TripleDESHelper.Decrypt(cipher, "my-secret-key"));
    }

    /// <summary>
    /// 验证字节数组的TripleDES加密解密往返一致性
    /// </summary>
    [Fact]
    public void EncryptDecrypt_Bytes_RoundTrips()
    {
        var plain = System.Text.Encoding.UTF8.GetBytes("hello 3des");
        var key = SecurityHelper.GenerateRandomBytes(24);
        var iv = SecurityHelper.GenerateRandomBytes(8);
        var cipher = TripleDESHelper.Encrypt(plain, key, iv);
        Assert.Equal(plain, TripleDESHelper.Decrypt(cipher, key, iv));
    }

    /// <summary>
    /// 验证TripleDES加密具有确定性
    /// </summary>
    [Fact]
    public void Encrypt_IsDeterministic()
    {
        var a = TripleDESHelper.Encrypt("data", "key");
        var b = TripleDESHelper.Encrypt("data", "key");
        Assert.Equal(a, b);
    }

    /// <summary>
    /// 验证使用错误密钥解密时失败（CBC模式填充错误或结果不匹配）
    /// </summary>
    [Fact]
    public void Decrypt_WithWrongKey_Fails()
    {
        var cipher = TripleDESHelper.Encrypt("secret data", "correct-key");
        try
        {
            var result = TripleDESHelper.Decrypt(cipher, "wrong-key-different");
            Assert.NotEqual("secret data", result);
        }
        catch (CryptographicException)
        {
            // CBC padding failure is the expected failure mode.
        }
    }

    /// <summary>
    /// 验证对空或null明文进行TripleDES加密时抛出异常
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Encrypt_NullOrEmptyPlain_Throws(string? plain)
    {
        Assert.ThrowsAny<ArgumentException>(() => TripleDESHelper.Encrypt(plain!, "key"));
    }
}