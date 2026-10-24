using System.Security.Cryptography;
using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Symmetric;

public class ChaCha20Poly1305HelperTests
{
    [Fact]
    public void EncryptDecrypt_String_RoundTrips()
    {
        var plain = "测试 Test 123 🔒";
        var cipher = ChaCha20Poly1305Helper.Encrypt(plain, "my-secret-key", "my-nonce");
        Assert.Equal(plain, ChaCha20Poly1305Helper.Decrypt(cipher, "my-secret-key", "my-nonce"));
    }

    [Fact]
    public void EncryptDecrypt_Bytes_RoundTrips()
    {
        var plain = System.Text.Encoding.UTF8.GetBytes("hello chacha");
        var key = Convert.FromBase64String(ChaCha20Poly1305Helper.GenerateKey());
        var nonce = Convert.FromBase64String(ChaCha20Poly1305Helper.GenerateNonce());
        var cipher = ChaCha20Poly1305Helper.Encrypt(plain, key, nonce);
        Assert.Equal(plain, ChaCha20Poly1305Helper.Decrypt(cipher, key, nonce));
    }

    [Fact]
    public void GenerateNonce_ReturnsSixteenBase64CharsForTwelveBytes()
    {
        var nonce = ChaCha20Poly1305Helper.GenerateNonce();
        // 12 bytes -> 16 base64 chars (no padding, 12 is a multiple of 3).
        Assert.Equal(16, nonce.Length);
        Assert.Equal(12, Convert.FromBase64String(nonce).Length);
    }

    [Fact]
    public void GenerateKey_ReturnsNonEmptyBase64DecodingTo32Bytes()
    {
        var key = ChaCha20Poly1305Helper.GenerateKey();
        Assert.False(string.IsNullOrEmpty(key));
        Assert.Equal(32, Convert.FromBase64String(key).Length);
    }

    [Fact]
    public void Decrypt_WithWrongKey_Throws()
    {
        var cipher = ChaCha20Poly1305Helper.Encrypt("secret", "correct-key", "nonce");
        Assert.ThrowsAny<CryptographicException>(() =>
            ChaCha20Poly1305Helper.Decrypt(cipher, "wrong-key-different", "nonce"));
    }

    [Fact]
    public void Decrypt_WithWrongNonce_Throws()
    {
        var cipher = ChaCha20Poly1305Helper.Encrypt("secret", "correct-key", "nonce-1");
        Assert.ThrowsAny<CryptographicException>(() =>
            ChaCha20Poly1305Helper.Decrypt(cipher, "correct-key", "nonce-2"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Encrypt_NullOrEmptyPlain_Throws(string? plain)
    {
        Assert.ThrowsAny<ArgumentException>(() => ChaCha20Poly1305Helper.Encrypt(plain!, "key", "nonce"));
    }
}
