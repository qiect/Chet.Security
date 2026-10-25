using System.Security.Cryptography;
using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Symmetric;

/// <summary>
/// RC2对称加密算法单元测试
/// </summary>
public class RC2HelperTests
{
    /// <summary>
    /// 验证字符串的RC2加密解密往返一致性
    /// </summary>
    [Fact]
    public void EncryptDecrypt_String_RoundTrips()
    {
        var plain = "测试 Test 123 🔒";
        var cipher = RC2Helper.Encrypt(plain, "my-secret-key");
        Assert.Equal(plain, RC2Helper.Decrypt(cipher, "my-secret-key"));
    }

    /// <summary>
    /// 验证字节数组的RC2加密解密往返一致性
    /// </summary>
    [Fact]
    public void EncryptDecrypt_Bytes_RoundTrips()
    {
        var plain = System.Text.Encoding.UTF8.GetBytes("hello rc2");
        var key = SecurityHelper.GenerateRandomBytes(16);
        var iv = SecurityHelper.GenerateRandomBytes(8);
        var cipher = RC2Helper.Encrypt(plain, key, iv);
        Assert.Equal(plain, RC2Helper.Decrypt(cipher, key, iv));
    }

    /// <summary>
    /// 验证RC2加密具有确定性
    /// </summary>
    [Fact]
    public void Encrypt_IsDeterministic()
    {
        var a = RC2Helper.Encrypt("data", "key");
        var b = RC2Helper.Encrypt("data", "key");
        Assert.Equal(a, b);
    }

    /// <summary>
    /// 验证使用错误密钥解密时失败（CBC模式填充错误或结果不匹配）
    /// </summary>
    [Fact]
    public void Decrypt_WithWrongKey_Fails()
    {
        var cipher = RC2Helper.Encrypt("secret data", "correct-key");
        try
        {
            var result = RC2Helper.Decrypt(cipher, "wrong-key-different");
            Assert.NotEqual("secret data", result);
        }
        catch (CryptographicException)
        {
            // CBC padding failure is the expected failure mode.
        }
    }

    /// <summary>
    /// 验证对空或null明文进行RC2加密时抛出异常
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Encrypt_NullOrEmptyPlain_Throws(string? plain)
    {
        Assert.ThrowsAny<ArgumentException>(() => RC2Helper.Encrypt(plain!, "key"));
    }
}