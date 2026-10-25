using System.Security.Cryptography;
using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Symmetric;

/// <summary>
/// SM4（国密对称加密算法）单元测试
/// </summary>
public class SM4HelperTests
{
    /// <summary>
    /// 验证字符串的SM4加密解密往返一致性
    /// </summary>
    [Fact]
    public void EncryptDecrypt_String_RoundTrips()
    {
        var plain = "测试 Test 123 🔒";
        var cipher = SM4Helper.Encrypt(plain, "my-secret-key", "my-iv-vector");
        Assert.Equal(plain, SM4Helper.Decrypt(cipher, "my-secret-key", "my-iv-vector"));
    }

    /// <summary>
    /// 验证字节数组的SM4加密解密往返一致性
    /// </summary>
    [Fact]
    public void EncryptDecrypt_Bytes_RoundTrips()
    {
        var plain = System.Text.Encoding.UTF8.GetBytes("hello sm4");
        var key = SecurityHelper.GenerateRandomBytes(16);
        var iv = SecurityHelper.GenerateRandomBytes(16);
        var cipher = SM4Helper.Encrypt(plain, key, iv);
        Assert.Equal(plain, SM4Helper.Decrypt(cipher, key, iv));
    }

    /// <summary>
    /// 验证SM4加密具有确定性
    /// </summary>
    [Fact]
    public void Encrypt_IsDeterministic()
    {
        var a = SM4Helper.Encrypt("data", "key", "iv");
        var b = SM4Helper.Encrypt("data", "key", "iv");
        Assert.Equal(a, b);
    }

    /// <summary>
    /// 验证SM4加密结果与明文不同
    /// </summary>
    [Fact]
    public void Encrypt_DiffersFromPlaintext()
    {
        var cipher = SM4Helper.Encrypt("data", "key", "iv");
        Assert.NotEqual("data", cipher);
    }

    /// <summary>
    /// 验证使用错误密钥解密时失败（BouncyCastle SM4抛出InvalidCipherTextException）
    /// </summary>
    [Fact]
    public void Decrypt_WithWrongKey_Fails()
    {
        var cipher = SM4Helper.Encrypt("secret data", "correct-key", "iv-value");
        try
        {
            var result = SM4Helper.Decrypt(cipher, "wrong-key-different", "iv-value");
            Assert.NotEqual("secret data", result);
        }
        catch (Exception)
        {
            // BouncyCastle SM4 CBC 在密钥错误时通常抛 InvalidCipherTextException（CryptoException 派生），
            // 而非 BCL 的 CryptographicException；此处接受任何异常视为解密失败。
        }
    }

    /// <summary>
    /// 验证对空或null明文进行SM4加密时抛出异常
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Encrypt_NullOrEmptyPlain_Throws(string? plain)
    {
        Assert.ThrowsAny<ArgumentException>(() => SM4Helper.Encrypt(plain!, "key", "iv"));
    }
}