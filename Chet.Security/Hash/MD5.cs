namespace Chet.Security;

/// <summary>
/// MD5 摘要工具类，输出长度固定为 128 位（16 字节，32 字符十六进制）。
/// 注意：MD5 已不满足抗碰撞要求，<b>不应用于密码存储或安全场景</b>，仅适用于校验和/指纹等非安全用途。
/// </summary>
public static class MD5Helper
{
    /// <summary>计算字节数组的 MD5 摘要，返回小写十六进制字符串。</summary>
    /// <param name="data">待计算的字节数据。</param>
    /// <returns>32 字符长度的小写十六进制摘要。</returns>
    public static string ComputeHash(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        return CryptoPolyfill.ToHexLower(ComputeHashBytes(data));
    }

    /// <summary>将字符串按 UTF-8 编码后计算 MD5 摘要，返回小写十六进制字符串。</summary>
    /// <param name="text">待计算的字符串。</param>
    /// <returns>32 字符长度的小写十六进制摘要。</returns>
    public static string ComputeHash(string text)
    {
        CryptoPolyfill.ThrowIfNull(text, nameof(text));
        return ComputeHash(Encoding.UTF8.GetBytes(text));
    }

    /// <summary>计算字节数组的 MD5 摘要，返回 Base64 字符串。</summary>
    /// <param name="data">待计算的字节数据。</param>
    /// <returns>Base64 编码的摘要字符串。</returns>
    public static string ComputeHashBase64(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        return Convert.ToBase64String(ComputeHashBytes(data));
    }

    /// <summary>将字符串按 UTF-8 编码后计算 MD5 摘要，返回 Base64 字符串。</summary>
    /// <param name="text">待计算的字符串。</param>
    /// <returns>Base64 编码的摘要字符串。</returns>
    public static string ComputeHashBase64(string text)
    {
        CryptoPolyfill.ThrowIfNull(text, nameof(text));
        return ComputeHashBase64(Encoding.UTF8.GetBytes(text));
    }

    /// <summary>计算字节数组的 MD5 摘要，返回原始字节数组（16 字节）。</summary>
    /// <param name="data">待计算的字节数据。</param>
    /// <returns>16 字节长度的原始摘要。</returns>
    public static byte[] ComputeHashBytes(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        using var md5 = MD5.Create();
        return md5.ComputeHash(data);
    }

    /// <summary>读取文件并计算其 MD5 摘要，返回小写十六进制字符串。</summary>
    /// <param name="filePath">文件绝对或相对路径。</param>
    /// <returns>32 字符长度的小写十六进制摘要。</returns>
    /// <exception cref="FileNotFoundException">文件不存在时抛出。</exception>
    public static string ComputeFileHash(string filePath)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(filePath, nameof(filePath));
        if (!File.Exists(filePath))
            throw new FileNotFoundException("Specified file was not found.", filePath);
        using var stream = File.OpenRead(filePath);
        using var md5 = MD5.Create();
        return CryptoPolyfill.ToHexLower(md5.ComputeHash(stream));
    }
}
