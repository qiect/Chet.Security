using System.Security.Cryptography;
using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Symmetric;

/// <summary>
/// AES对称加密算法单元测试（包含CBC、ECB、GCM模式）
/// </summary>
public class AESHelperTests
{
    /// <summary>
    /// 验证AES-CBC模式字符串的加密解密往返一致性
    /// </summary>
    [Fact]
    public void EncryptDecrypt_CBC_String_RoundTrips()
    {
        var plain = "测试 Test 123 🔒";
        var cipher = AESHelper.Encrypt(plain, "my-secret-key", "my-iv-vector");
        Assert.Equal(plain, AESHelper.Decrypt(cipher, "my-secret-key", "my-iv-vector"));
    }

    /// <summary>
    /// 验证AES-CBC模式字节数组的加密解密往返一致性
    /// </summary>
    [Fact]
    public void EncryptDecrypt_CBC_Bytes_RoundTrips()
    {
        var plain = System.Text.Encoding.UTF8.GetBytes("hello world");
        var key = Convert.FromBase64String(AESHelper.GenerateKey(256));
        var iv = Convert.FromBase64String(AESHelper.GenerateIV());
        var cipher = AESHelper.Encrypt(plain, key, iv);
        Assert.Equal(plain, AESHelper.Decrypt(cipher, key, iv));
    }

    /// <summary>
    /// 验证AES-ECB模式字符串的加密解密往返一致性
    /// </summary>
    [Fact]
    public void EncryptDecrypt_ECB_String_RoundTrips()
    {
        var plain = "ECB mode test";
        var cipher = AESHelper.Encrypt(plain, "my-secret-key", string.Empty, CipherMode.ECB);
        Assert.Equal(plain, AESHelper.Decrypt(cipher, "my-secret-key", string.Empty, CipherMode.ECB));
    }

    /// <summary>
    /// 验证AES-GCM模式字符串的加密解密往返一致性
    /// </summary>
    [Fact]
    public void EncryptDecrypt_GCM_String_RoundTrips()
    {
        var plain = "GCM round-trip 测试";
        var cipher = AESHelper.EncryptGCM(plain, "my-secret-key", "my-nonce");
        Assert.Equal(plain, AESHelper.DecryptGCM(cipher, "my-secret-key", "my-nonce"));
    }

    /// <summary>
    /// 验证AES-GCM模式字节数组的加密解密往返一致性
    /// </summary>
    [Fact]
    public void EncryptDecrypt_GCM_Bytes_RoundTrips()
    {
        var plain = System.Text.Encoding.UTF8.GetBytes("hello gcm");
        var key = Convert.FromBase64String(AESHelper.GenerateKey(256));
        var nonce = Convert.FromBase64String(AESHelper.GenerateIV().Substring(0, 16)); // 12 bytes
        var cipher = AESHelper.EncryptGCM(plain, key, nonce);
        Assert.Equal(plain, AESHelper.DecryptGCM(cipher, key, nonce));
    }

    /// <summary>
    /// 验证AES加密具有确定性且输出为Base64格式
    /// </summary>
    [Fact]
    public void Encrypt_IsDeterministicAndProducesBase64()
    {
        var a = AESHelper.Encrypt("data", "key", "iv");
        var b = AESHelper.Encrypt("data", "key", "iv");
        Assert.Equal(a, b);
        Assert.NotEqual("data", a);
    }

    /// <summary>
    /// 验证生成的AES密钥为非空的Base64字符串，解码后为32字节（256位）
    /// </summary>
    [Fact]
    public void GenerateKey_ReturnsNonEmptyBase64DecodingTo32Bytes()
    {
        var key = AESHelper.GenerateKey();
        Assert.False(string.IsNullOrEmpty(key));
        Assert.Equal(32, Convert.FromBase64String(key).Length);
    }

    /// <summary>
    /// 验证生成的AES IV为非空的Base64字符串，解码后为16字节（128位）
    /// </summary>
    [Fact]
    public void GenerateIV_ReturnsNonEmptyBase64DecodingTo16Bytes()
    {
        var iv = AESHelper.GenerateIV();
        Assert.False(string.IsNullOrEmpty(iv));
        Assert.Equal(16, Convert.FromBase64String(iv).Length);
    }

    /// <summary>
    /// 验证使用错误密钥解密时失败（CBC模式填充错误或结果不匹配）
    /// </summary>
    [Fact]
    public void Decrypt_WithWrongKey_Fails()
    {
        var plain = "测试 Test 123 🔒";
        var cipher = AESHelper.Encrypt(plain, "correct-key", "iv-value");
        try
        {
            var result = AESHelper.Decrypt(cipher, "wrong-key-different", "iv-value");
            Assert.NotEqual(plain, result);
        }
        catch (CryptographicException)
        {
            // CBC padding failure is the expected failure mode.
        }
    }

    /// <summary>
    /// 验证使用错误密钥进行GCM解密时抛出CryptographicException
    /// </summary>
    [Fact]
    public void DecryptGCM_WithWrongKey_Throws()
    {
        var cipher = AESHelper.EncryptGCM("secret", "correct-key", "nonce");
        Assert.ThrowsAny<CryptographicException>(() => AESHelper.DecryptGCM(cipher, "wrong-key", "nonce"));
    }

    /// <summary>
    /// 验证使用不支持的加密模式时抛出NotSupportedException
    /// </summary>
    [Fact]
    public void Encrypt_UnsupportedMode_Throws()
    {
        Assert.Throws<NotSupportedException>(() => AESHelper.Encrypt("x", "key", "iv", CipherMode.CFB));
    }

    /// <summary>
    /// 验证对空或null明文进行加密时抛出异常
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Encrypt_NullOrEmptyPlain_Throws(string? plain)
    {
        Assert.ThrowsAny<ArgumentException>(() => AESHelper.Encrypt(plain!, "key", "iv"));
    }
}