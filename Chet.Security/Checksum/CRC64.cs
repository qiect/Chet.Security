namespace Chet.Security;

/// <summary>
/// CRC64 校验和工具类（ISO 3309 / ECMA-182 反射变体，多项式 0xC96C5795D7870F42，
/// 初始值 0、不输出反射），提供字节、字符串与文件级校验和计算。
/// </summary>
public static class CRC64Helper
{
    private const ulong Polynomial = 0xC96C5795D7870F42u;
    private const ulong InitialValue = 0uL;
    private const ulong FinalXor = 0uL;

    private static readonly ulong[] s_table = BuildTable();

    private static ulong[] BuildTable()
    {
        var t = new ulong[256];
        for (uint i = 0; i < 256; i++)
        {
            ulong c = i;
            for (int k = 0; k < 8; k++)
                c = (c & 1uL) != 0uL ? (Polynomial ^ (c >> 1)) : (c >> 1);
            t[i] = c;
        }
        return t;
    }

    /// <summary>计算给定字节数组的 CRC64 校验和（64 位无符号整数）。</summary>
    /// <param name="data">输入字节数组。</param>
    /// <returns>CRC64 校验和。</returns>
    public static ulong Compute(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        ulong crc = InitialValue;
        for (int i = 0; i < data.Length; i++)
            crc = s_table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
        return crc ^ FinalXor;
    }

    /// <summary>计算给定字节数组的 CRC64 校验和，并以小写十六进制返回。</summary>
    public static string ComputeHex(byte[] data) => Compute(data).ToString("x");

    /// <summary>将字符串按 UTF-8 编码后计算 CRC64 校验和，并以小写十六进制返回。</summary>
    public static string ComputeHex(string text)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(text, nameof(text));
        return ComputeHex(Encoding.UTF8.GetBytes(text));
    }

    /// <summary>分块读取文件并计算 CRC64 校验和，返回小写十六进制。</summary>
    /// <param name="filePath">文件路径。</param>
    /// <returns>CRC64 校验和（小写十六进制）。</returns>
    public static string ComputeFileHex(string filePath)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(filePath, nameof(filePath));
        if (!File.Exists(filePath)) throw new FileNotFoundException("File not found.", filePath);

        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 8192);
        var buffer = new byte[8192];
        ulong crc = InitialValue;
        int read;
        while ((read = fs.Read(buffer, 0, buffer.Length)) > 0)
        {
            for (int i = 0; i < read; i++)
                crc = s_table[(crc ^ buffer[i]) & 0xFFu] ^ (crc >> 8);
        }
        return (crc ^ FinalXor).ToString("x");
    }

    /// <summary>计算 CRC64 校验和并以 8 字节小端序返回。</summary>
    public static byte[] ComputeBytes(byte[] data)
    {
        ulong crc = Compute(data);
        return new byte[]
        {
            (byte)crc,
            (byte)(crc >> 8),
            (byte)(crc >> 16),
            (byte)(crc >> 24),
            (byte)(crc >> 32),
            (byte)(crc >> 40),
            (byte)(crc >> 48),
            (byte)(crc >> 56),
        };
    }
}
