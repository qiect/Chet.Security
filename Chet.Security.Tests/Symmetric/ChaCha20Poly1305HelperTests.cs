using System.Security.Cryptography;
using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Symmetric;

/// <summary>
/// ChaCha20-Poly1305认证加密算法单元测试
/// </summary>
public class ChaCha20Poly1305HelperTests
{
    /// <summary>
    /// 验证字符串的ChaCha20-Poly1305加密解密往返一致性
    /// </summary>
    [Fact]
    public void EncryptDecrypt_String_RoundTrips()
    {
        var plain = "测试 Test 123 🔒";
        var cipher = ChaCha20Poly1305Helper.Encrypt(plain, "my-secret-key", "my-nonce");
        Assert.Equal(plain, ChaCha20Poly1305Helper.Decrypt(cipher, "my-secret-key", "my-nonce"));
    }

    /// <summary>
    /// 验证字节数组的ChaCha20-Poly1305加密解密往返一致性
    /// </summary>
    [Fact]
    public void EncryptDecrypt_Bytes_RoundTrips()
    {
        var plain = System.Text.Encoding.UTF8.GetBytes("hello chacha");
        var key = Convert.FromBase64String(ChaCha20Poly1305Helper.GenerateKey());
        var nonce = Convert.FromBase64String(ChaCha20Poly1305Helper.GenerateNonce());
        var cipher = ChaCha20Poly1305Helper.Encrypt(plain, key, nonce);
        Assert.Equal(plain, ChaCha20Poly1305Helper.Decrypt(cipher, key, nonce));
    }

    /// <summary>
    /// 验证生成的nonce为16个Base64字符（12字节）
    /// </summary>
    [Fact]
    public void GenerateNonce_ReturnsSixteenBase64CharsForTwelveBytes()
    {
        var nonce = ChaCha20Poly1305Helper.GenerateNonce();
        // 12 bytes -> 16 base64 chars (no padding, 12 is a multiple of 3).
        Assert.Equal(16, nonce.Length);
        Assert.Equal(12, Convert.FromBase64String(nonce).Length);
    }

    /// <summary>
    /// 验证生成的密钥为非空的Base64字符串，解码后为32字节（256位）
    /// </summary>
    [Fact]
    public void GenerateKey_ReturnsNonEmptyBase64DecodingTo32Bytes()
    {
        var key = ChaCha20Poly1305Helper.GenerateKey();
        Assert.False(string.IsNullOrEmpty(key));
        Assert.Equal(32, Convert.FromBase64String(key).Length);
    }

    /// <summary>
    /// 验证使用错误密钥解密时抛出CryptographicException
    /// </summary>
    [Fact]
    public void Decrypt_WithWrongKey_Throws()
    {
        var cipher = ChaCha20Poly1305Helper.Encrypt("secret", "correct-key", "nonce");
        Assert.ThrowsAny<CryptographicException>(() =>
            ChaCha20Poly1305Helper.Decrypt(cipher, "wrong-key-different", "nonce"));
    }

    /// <summary>
    /// 验证使用错误nonce解密时抛出CryptographicException
    /// </summary>
    [Fact]
    public void Decrypt_WithWrongNonce_Throws()
    {
        var cipher = ChaCha20Poly1305Helper.Encrypt("secret", "correct-key", "nonce-1");
        Assert.ThrowsAny<CryptographicException>(() =>
            ChaCha20Poly1305Helper.Decrypt(cipher, "correct-key", "nonce-2"));
    }

    /// <summary>
    /// 验证对空或null明文进行加密时抛出异常
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Encrypt_NullOrEmptyPlain_Throws(string? plain)
    {
        Assert.ThrowsAny<ArgumentException>(() => ChaCha20Poly1305Helper.Encrypt(plain!, "key", "nonce"));
    }
}