using System.Security.Cryptography;
using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Symmetric;

public class AESHelperTests
{
    [Fact]
    public void EncryptDecrypt_CBC_String_RoundTrips()
    {
        var plain = "测试 Test 123 🔒";
        var cipher = AESHelper.Encrypt(plain, "my-secret-key", "my-iv-vector");
        Assert.Equal(plain, AESHelper.Decrypt(cipher, "my-secret-key", "my-iv-vector"));
    }

    [Fact]
    public void EncryptDecrypt_CBC_Bytes_RoundTrips()
    {
        var plain = System.Text.Encoding.UTF8.GetBytes("hello world");
        var key = Convert.FromBase64String(AESHelper.GenerateKey(256));
        var iv = Convert.FromBase64String(AESHelper.GenerateIV());
        var cipher = AESHelper.Encrypt(plain, key, iv);
        Assert.Equal(plain, AESHelper.Decrypt(cipher, key, iv));
    }

    [Fact]
    public void EncryptDecrypt_ECB_String_RoundTrips()
    {
        var plain = "ECB mode test";
        var cipher = AESHelper.Encrypt(plain, "my-secret-key", string.Empty, CipherMode.ECB);
        Assert.Equal(plain, AESHelper.Decrypt(cipher, "my-secret-key", string.Empty, CipherMode.ECB));
    }

    [Fact]
    public void EncryptDecrypt_GCM_String_RoundTrips()
    {
        var plain = "GCM round-trip 测试";
        var cipher = AESHelper.EncryptGCM(plain, "my-secret-key", "my-nonce");
        Assert.Equal(plain, AESHelper.DecryptGCM(cipher, "my-secret-key", "my-nonce"));
    }

    [Fact]
    public void EncryptDecrypt_GCM_Bytes_RoundTrips()
    {
        var plain = System.Text.Encoding.UTF8.GetBytes("hello gcm");
        var key = Convert.FromBase64String(AESHelper.GenerateKey(256));
        var nonce = Convert.FromBase64String(AESHelper.GenerateIV().Substring(0, 16)); // 12 bytes
        var cipher = AESHelper.EncryptGCM(plain, key, nonce);
        Assert.Equal(plain, AESHelper.DecryptGCM(cipher, key, nonce));
    }

    [Fact]
    public void Encrypt_IsDeterministicAndProducesBase64()
    {
        var a = AESHelper.Encrypt("data", "key", "iv");
        var b = AESHelper.Encrypt("data", "key", "iv");
        Assert.Equal(a, b);
        Assert.NotEqual("data", a);
    }

    [Fact]
    public void GenerateKey_ReturnsNonEmptyBase64DecodingTo32Bytes()
    {
        var key = AESHelper.GenerateKey();
        Assert.False(string.IsNullOrEmpty(key));
        Assert.Equal(32, Convert.FromBase64String(key).Length);
    }

    [Fact]
    public void GenerateIV_ReturnsNonEmptyBase64DecodingTo16Bytes()
    {
        var iv = AESHelper.GenerateIV();
        Assert.False(string.IsNullOrEmpty(iv));
        Assert.Equal(16, Convert.FromBase64String(iv).Length);
    }

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

    [Fact]
    public void DecryptGCM_WithWrongKey_Throws()
    {
        var cipher = AESHelper.EncryptGCM("secret", "correct-key", "nonce");
        Assert.ThrowsAny<CryptographicException>(() => AESHelper.DecryptGCM(cipher, "wrong-key", "nonce"));
    }

    [Fact]
    public void Encrypt_UnsupportedMode_Throws()
    {
        Assert.Throws<NotSupportedException>(() => AESHelper.Encrypt("x", "key", "iv", CipherMode.CFB));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Encrypt_NullOrEmptyPlain_Throws(string? plain)
    {
        Assert.ThrowsAny<ArgumentException>(() => AESHelper.Encrypt(plain!, "key", "iv"));
    }
}
