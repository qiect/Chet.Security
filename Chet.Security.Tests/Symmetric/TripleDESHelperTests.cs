using System.Security.Cryptography;
using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Symmetric;

public class TripleDESHelperTests
{
    [Fact]
    public void EncryptDecrypt_String_RoundTrips()
    {
        var plain = "测试 Test 123 🔒";
        var cipher = TripleDESHelper.Encrypt(plain, "my-secret-key");
        Assert.Equal(plain, TripleDESHelper.Decrypt(cipher, "my-secret-key"));
    }

    [Fact]
    public void EncryptDecrypt_Bytes_RoundTrips()
    {
        var plain = System.Text.Encoding.UTF8.GetBytes("hello 3des");
        var key = SecurityHelper.GenerateRandomBytes(24);
        var iv = SecurityHelper.GenerateRandomBytes(8);
        var cipher = TripleDESHelper.Encrypt(plain, key, iv);
        Assert.Equal(plain, TripleDESHelper.Decrypt(cipher, key, iv));
    }

    [Fact]
    public void Encrypt_IsDeterministic()
    {
        var a = TripleDESHelper.Encrypt("data", "key");
        var b = TripleDESHelper.Encrypt("data", "key");
        Assert.Equal(a, b);
    }

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

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Encrypt_NullOrEmptyPlain_Throws(string? plain)
    {
        Assert.ThrowsAny<ArgumentException>(() => TripleDESHelper.Encrypt(plain!, "key"));
    }
}
