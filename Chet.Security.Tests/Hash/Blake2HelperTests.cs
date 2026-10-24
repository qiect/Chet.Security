using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.Hash;

public class Blake2HelperTests
{
    [Fact]
    public void Blake2b_HasOneHundredTwentyEightHexChars()
    {
        Assert.Equal(128, Blake2Helper.ComputeBlake2b("hello").Length);
    }

    [Fact]
    public void Blake2s_HasSixtyFourHexChars()
    {
        Assert.Equal(64, Blake2Helper.ComputeBlake2s("hello").Length);
    }

    [Fact]
    public void Blake2bBytes_ReturnsSixtyFourBytes()
    {
        Assert.Equal(64, Blake2Helper.ComputeBlake2bBytes(System.Text.Encoding.UTF8.GetBytes("hello")).Length);
    }

    [Fact]
    public void Blake2sBytes_ReturnsThirtyTwoBytes()
    {
        Assert.Equal(32, Blake2Helper.ComputeBlake2sBytes(System.Text.Encoding.UTF8.GetBytes("hello")).Length);
    }

    [Fact]
    public void Blake2b_IsDeterministic()
    {
        Assert.Equal(Blake2Helper.ComputeBlake2b("a"), Blake2Helper.ComputeBlake2b("a"));
    }

    [Fact]
    public void Blake2b_IsInputSensitive()
    {
        Assert.NotEqual(Blake2Helper.ComputeBlake2b("a"), Blake2Helper.ComputeBlake2b("b"));
    }

    [Fact]
    public void Blake2s_IsInputSensitive()
    {
        Assert.NotEqual(Blake2Helper.ComputeBlake2s("a"), Blake2Helper.ComputeBlake2s("b"));
    }

    [Fact]
    public void Blake2b_KeyedDiffersFromUnkeyed()
    {
        var unkeyed = Blake2Helper.ComputeBlake2b("data");
        var keyed = Blake2Helper.ComputeBlake2b(System.Text.Encoding.UTF8.GetBytes("data"),
            System.Text.Encoding.UTF8.GetBytes("key"));
        Assert.NotEqual(unkeyed, keyed);
        Assert.Equal(128, keyed.Length);
    }

    [Fact]
    public void Blake2b_KeyedWithEmptyKeyEqualsUnkeyed()
    {
        var unkeyed = Blake2Helper.ComputeBlake2b("data");
        var emptyKey = Blake2Helper.ComputeBlake2b(System.Text.Encoding.UTF8.GetBytes("data"), Array.Empty<byte>());
        Assert.Equal(unkeyed, emptyKey);
    }

    [Fact]
    public void Blake2b_NullBytes_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Blake2Helper.ComputeBlake2b((byte[])null!));
    }

    [Fact]
    public void Blake2bString_Null_Throws()
    {
        Assert.ThrowsAny<ArgumentException>(() => Blake2Helper.ComputeBlake2b((string)null!));
    }
}
