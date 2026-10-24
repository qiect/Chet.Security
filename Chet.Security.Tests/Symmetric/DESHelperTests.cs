using System.Security.Cryptography;
using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Symmetric;

public class DESHelperTests
{
    [Fact]
    public void EncryptDecrypt_String_RoundTrips()
    {
        var plain = "测试 Test 123 🔒";
        var cipher = DESHelper.Encrypt(plain, "my-secret-key");
        Assert.Equal(plain, DESHelper.Decrypt(cipher, "my-secret-key"));
    }

    [Fact]
    public void EncryptDecrypt_Bytes_RoundTrips()
    {
        var plain = System.Text.Encoding.UTF8.GetBytes("hello des");
        var key = SecurityHelper.GenerateRandomBytes(8);
        var iv = SecurityHelper.GenerateRandomBytes(8);
        var cipher = DESHelper.Encrypt(plain, key, iv);
        Assert.Equal(plain, DESHelper.Decrypt(cipher, key, iv));
    }

    [Fact]
    public void Encrypt_IsDeterministic()
    {
        var a = DESHelper.Encrypt("data", "key");
        var b = DESHelper.Encrypt("data", "key");
        Assert.Equal(a, b);
    }

    [Fact]
    public void Decrypt_WithWrongKey_Fails()
    {
        var cipher = DESHelper.Encrypt("secret data", "correct-key");
        try
        {
            var result = DESHelper.Decrypt(cipher, "wrong-key-different");
            Assert.NotEqual("secret data", result);
        }
        catch (CryptographicException)
        {
            // CBC padding failure is the expected failure mode.
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Encrypt_NullOrEmptyPlain_Throws(string? plain)
    {
        Assert.ThrowsAny<ArgumentException>(() => DESHelper.Encrypt(plain!, "key"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Decrypt_NullOrEmptyCipher_Throws(string? cipher)
    {
        Assert.ThrowsAny<ArgumentException>(() => DESHelper.Decrypt(cipher!, "key"));
    }
}
