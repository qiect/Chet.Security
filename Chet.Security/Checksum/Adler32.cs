namespace Chet.Security;

/// <summary>
/// Adler-32 校验和工具类（zlib 算法），提供字节、字符串与文件级校验和计算。
/// </summary>
public static class Adler32Helper
{
    private const uint Mod = 65521u;
    private const uint BaseA = 1u;

    /// <summary>计算给定字节数组的 Adler-32 校验和。</summary>
    /// <param name="data">输入字节数组。</param>
    /// <returns>Adler-32 校验和（32 位无符号整数）。</returns>
    public static uint Compute(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        uint a = BaseA;
        uint b = 0u;
        for (int i = 0; i < data.Length; i++)
        {
            a = (a + data[i]) % Mod;
            b = (b + a) % Mod;
        }
        return (b << 16) | a;
    }

    /// <summary>计算给定字节数组的 Adler-32 校验和，并以 8 字符小写十六进制返回。</summary>
    public static string ComputeHex(byte[] data) => Compute(data).ToString("x8");

    /// <summary>将字符串按 UTF-8 编码后计算 Adler-32 校验和，并以 8 字符小写十六进制返回。</summary>
    public static string ComputeHex(string text)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(text, nameof(text));
        return ComputeHex(Encoding.UTF8.GetBytes(text));
    }

    /// <summary>分块读取文件并计算 Adler-32 校验和，返回 8 字符小写十六进制。</summary>
    /// <param name="filePath">文件路径。</param>
    /// <returns>Adler-32 校验和（小写十六进制）。</returns>
    public static string ComputeFileHex(string filePath)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(filePath, nameof(filePath));
        if (!File.Exists(filePath)) throw new FileNotFoundException("File not found.", filePath);

        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 8192);
        var buffer = new byte[8192];
        uint a = BaseA;
        uint b = 0u;
        int read;
        while ((read = fs.Read(buffer, 0, buffer.Length)) > 0)
        {
            for (int i = 0; i < read; i++)
            {
                a = (a + buffer[i]) % Mod;
                b = (b + a) % Mod;
            }
        }
        return ((b << 16) | a).ToString("x8");
    }

    /// <summary>计算 Adler-32 校验和并以 4 字节小端序返回。</summary>
    public static byte[] ComputeBytes(byte[] data)
    {
        uint v = Compute(data);
        return new byte[]
        {
            (byte)v,
            (byte)(v >> 8),
            (byte)(v >> 16),
            (byte)(v >> 24),
        };
    }
}
