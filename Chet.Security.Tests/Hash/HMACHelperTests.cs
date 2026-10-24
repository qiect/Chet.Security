using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Hash;

public class HMACHelperTests
{
    [Fact]
    public void HmacSHA256_HasSixtyFourHexChars()
    {
        Assert.Equal(64, HMACHelper.ComputeHmacSHA256("Hi There", "secret-key").Length);
    }

    [Fact]
    public void HmacMD5_HasThirtyTwoHexChars()
    {
        Assert.Equal(32, HMACHelper.ComputeHmacMD5("Hi There", "secret-key").Length);
    }

    [Fact]
    public void HmacSHA1_HasFortyHexChars()
    {
        Assert.Equal(40, HMACHelper.ComputeHmacSHA1("Hi There", "secret-key").Length);
    }

    [Fact]
    public void HmacSHA384_HasNinetySixHexChars()
    {
        Assert.Equal(96, HMACHelper.ComputeHmacSHA384("Hi There", "secret-key").Length);
    }

    [Fact]
    public void HmacSHA512_HasOneHundredTwentyEightHexChars()
    {
        Assert.Equal(128, HMACHelper.ComputeHmacSHA512("Hi There", "secret-key").Length);
    }

    [Fact]
    public void HmacSM3_HasSixtyFourHexCharsAndNonEmpty()
    {
        var mac = HMACHelper.ComputeHmacSM3("Hi There", "secret-key");
        Assert.Equal(64, mac.Length);
        Assert.False(string.IsNullOrWhiteSpace(mac));
    }

    [Fact]
    public void HmacSHA256_IsDeterministic()
    {
        Assert.Equal(
            HMACHelper.ComputeHmacSHA256("message", "key"),
            HMACHelper.ComputeHmacSHA256("message", "key"));
    }

    [Fact]
    public void HmacSHA256_IsKeySensitive()
    {
        Assert.NotEqual(
            HMACHelper.ComputeHmacSHA256("message", "key1"),
            HMACHelper.ComputeHmacSHA256("message", "key2"));
    }

    [Fact]
    public void HmacSHA256_IsDataSensitive()
    {
        Assert.NotEqual(
            HMACHelper.ComputeHmacSHA256("message1", "key"),
            HMACHelper.ComputeHmacSHA256("message2", "key"));
    }

    [Fact]
    public void HmacSHA256Bytes_LengthIsThirtyTwo()
    {
        Assert.Equal(32,
            HMACHelper.ComputeHmacSHA256Bytes(System.Text.Encoding.UTF8.GetBytes("data"),
                System.Text.Encoding.UTF8.GetBytes("key")).Length);
    }

    [Fact]
    public void HmacSHA256_NullData_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => HMACHelper.ComputeHmacSHA256((byte[])null!, new byte[] { 1 }));
    }

    [Fact]
    public void HmacSHA256_NullKey_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => HMACHelper.ComputeHmacSHA256(new byte[] { 1 }, (byte[])null!));
    }

    [Fact]
    public void HmacSHA256_NullText_Throws()
    {
        Assert.ThrowsAny<ArgumentException>(() => HMACHelper.ComputeHmacSHA256((string)null!, "key"));
    }
}
