namespace Chet.Security;

/// <summary>
/// CRC32 校验和工具类（IEEE 802.3 / zip 多项式 0xEDB88320，反射输入输出），
/// 提供字节、字符串与文件级校验和计算。
/// </summary>
public static class CRC32Helper
{
    private const uint Polynomial = 0xEDB88320u;
    private const uint InitialValue = 0xFFFFFFFFu;
    private const uint FinalXor = 0xFFFFFFFFu;

    private static readonly uint[] s_table = BuildTable();

    private static uint[] BuildTable()
    {
        var t = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i;
            for (int k = 0; k < 8; k++)
                c = (c & 1u) != 0u ? (Polynomial ^ (c >> 1)) : (c >> 1);
            t[i] = c;
        }
        return t;
    }

    /// <summary>计算给定字节数组的 CRC32 校验和（32 位无符号整数）。</summary>
    /// <param name="data">输入字节数组。</param>
    /// <returns>CRC32 校验和。</returns>
    public static uint Compute(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        uint crc = InitialValue;
        for (int i = 0; i < data.Length; i++)
            crc = s_table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
        return crc ^ FinalXor;
    }

    /// <summary>计算给定字节数组的 CRC32 校验和，并以 8 字符小写十六进制返回。</summary>
    public static string ComputeHex(byte[] data) => Compute(data).ToString("x8");

    /// <summary>将字符串按 UTF-8 编码后计算 CRC32 校验和，并以 8 字符小写十六进制返回。</summary>
    public static string ComputeHex(string text)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(text, nameof(text));
        return ComputeHex(Encoding.UTF8.GetBytes(text));
    }

    /// <summary>分块读取文件并计算 CRC32 校验和，返回 8 字符小写十六进制。</summary>
    /// <param name="filePath">文件路径。</param>
    /// <returns>CRC32 校验和（小写十六进制）。</returns>
    public static string ComputeFileHex(string filePath)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(filePath, nameof(filePath));
        if (!File.Exists(filePath)) throw new FileNotFoundException("File not found.", filePath);

        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 8192);
        var buffer = new byte[8192];
        uint crc = InitialValue;
        int read;
        while ((read = fs.Read(buffer, 0, buffer.Length)) > 0)
        {
            for (int i = 0; i < read; i++)
                crc = s_table[(crc ^ buffer[i]) & 0xFFu] ^ (crc >> 8);
        }
        return (crc ^ FinalXor).ToString("x8");
    }

    /// <summary>计算 CRC32 校验和并以 4 字节小端序返回。</summary>
    public static byte[] ComputeBytes(byte[] data)
    {
        uint crc = Compute(data);
        return new byte[]
        {
            (byte)crc,
            (byte)(crc >> 8),
            (byte)(crc >> 16),
            (byte)(crc >> 24),
        };
    }
}
