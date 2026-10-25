using Chet.Security;
using Xunit;

namespace Chet.Security.Tests.KeyDerivation;

/// <summary>
/// BCrypt/PBKDF2密码哈希算法单元测试
/// </summary>
public class BCryptHelperTests
{
    /// <summary>
    /// 验证密码哈希返回符合格式规范的字符串（pbkdf2$迭代次数$盐$哈希）
    /// </summary>
    [Fact]
    public void HashPassword_ReturnsFormattedString()
    {
        var hash = BCryptHelper.HashPassword("my-password", iterations: 1000);
        Assert.StartsWith("pbkdf2$1000$", hash);
        Assert.Equal(4, hash.Split('$').Length);
    }

    /// <summary>
    /// 验证使用正确密码验证时返回true
    /// </summary>
    [Fact]
    public void VerifyPassword_CorrectPassword_ReturnsTrue()
    {
        var hash = BCryptHelper.HashPassword("my-password", iterations: 1000);
        Assert.True(BCryptHelper.VerifyPassword("my-password", hash));
    }

    /// <summary>
    /// 验证使用错误密码验证时返回false
    /// </summary>
    [Fact]
    public void VerifyPassword_WrongPassword_ReturnsFalse()
    {
        var hash = BCryptHelper.HashPassword("my-password", iterations: 1000);
        Assert.False(BCryptHelper.VerifyPassword("different-password", hash));
    }

    /// <summary>
    /// 验证不同次哈希同一密码产生不同结果（因随机盐值），但均能验证通过
    /// </summary>
    [Fact]
    public void HashPassword_DifferentCallsProduceDifferentHashes()
    {
        var a = BCryptHelper.HashPassword("my-password", iterations: 1000);
        var b = BCryptHelper.HashPassword("my-password", iterations: 1000);
        Assert.NotEqual(a, b);
        Assert.True(BCryptHelper.VerifyPassword("my-password", a));
        Assert.True(BCryptHelper.VerifyPassword("my-password", b));
    }

    /// <summary>
    /// 验证对无效格式的哈希字符串进行验证时返回false
    /// </summary>
    [Fact]
    public void VerifyPassword_InvalidFormat_ReturnsFalse()
    {
        Assert.False(BCryptHelper.VerifyPassword("password", "not-a-valid-hash"));
    }

    /// <summary>
    /// 验证对格式正确但内容无效的哈希字符串进行验证时返回false
    /// </summary>
    [Fact]
    public void VerifyPassword_GarbageBodyButValidShape_ReturnsFalse()
    {
        Assert.False(BCryptHelper.VerifyPassword("password", "pbkdf2$1000$not-base64!!!$also-bad=="));
    }

    /// <summary>
    /// 验证对空或null密码进行哈希时抛出异常
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void HashPassword_NullOrEmpty_Throws(string? password)
    {
        Assert.ThrowsAny<ArgumentException>(() => BCryptHelper.HashPassword(password!));
    }

    /// <summary>
    /// 验证使用非正迭代次数进行哈希时抛出异常
    /// </summary>
    [Fact]
    public void HashPassword_NonPositiveIterations_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => BCryptHelper.HashPassword("password", 0));
    }
}