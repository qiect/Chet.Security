namespace Chet.Security;

/// <summary>
/// Base58 编码/解码工具类，使用 Bitcoin 码表，去除易混淆字符（0/O/I/l），常用于比特币地址与短链接。
/// </summary>
public static class Base58Helper
{
    /// <summary>Bitcoin Base58 码表（无 0、O、I、l）。</summary>
    public const string BitcoinAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    private static readonly int[] s_indexMap = BuildIndexMap(BitcoinAlphabet);

    /// <summary>将字节数组编码为 Base58 字符串。</summary>
    public static string Encode(byte[] bytes)
    {
        if (bytes is null) throw new ArgumentNullException(nameof(bytes));
        if (bytes.Length == 0) return string.Empty;

        // 统计前导 0，对应前导 '1'
        int zeros = 0;
        while (zeros < bytes.Length && bytes[zeros] == 0) zeros++;

        // 大整数除法
        var input = new byte[bytes.Length - zeros];
        Buffer.BlockCopy(bytes, zeros, input, 0, input.Length);
        var output = new char[input.Length * 138 / 100 + 1]; // log(256)/log(58) ≈ 1.365
        int outputStart = output.Length;

        for (int inputStart = 0; inputStart < input.Length;)
        {
            int remainder = 0;
            int it = inputStart;
            for (; it < input.Length; it++)
            {
                int temp = input[it] + (remainder << 8);
                input[it] = (byte)(temp / 58);
                remainder = temp % 58;
            }
            output[--outputStart] = BitcoinAlphabet[remainder];
            // 跳过已变 0 的高位
            if (input[inputStart] == 0) inputStart++;
        }

        // 输出末尾的全 0 前缀补 1
        var result = new char[zeros + (output.Length - outputStart)];
        for (int i = 0; i < zeros; i++) result[i] = BitcoinAlphabet[0];
        Buffer.BlockCopy(output, outputStart * sizeof(char), result, zeros * sizeof(char), (output.Length - outputStart) * sizeof(char));
        return new string(result);
    }

    /// <summary>将字符串按 UTF-8 编码后转为 Base58。</summary>
    public static string EncodeString(string text)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(text, nameof(text));
        return Encode(System.Text.Encoding.UTF8.GetBytes(text));
    }

    /// <summary>将 Base58 字符串解码为字节数组。</summary>
    public static byte[] Decode(string base58)
    {
        CryptoPolyfill.ThrowIfNullOrEmpty(base58, nameof(base58));

        int p = 0;
        // 跳过前导空白
        while (p < base58.Length && char.IsWhiteSpace(base58[p])) p++;
        // 统计前导 '1'
        int zeros = 0;
        while (p < base58.Length && base58[p] == BitcoinAlphabet[0]) { zeros++; p++; }

        // 分配大端缓冲区：每字符约 0.732 字节
        int size = (base58.Length - p) * 733 / 1000 + 1;
        var bytes = new byte[size];
        int length = 0; // 已使用的有效字节数（从右起）

        for (; p < base58.Length; p++)
        {
            if (char.IsWhiteSpace(base58[p])) continue;
            int value = base58[p] < 256 ? s_indexMap[base58[p]] : -1;
            if (value < 0) throw new FormatException($"Invalid Base58 character: {base58[p]}");

            int carry = value;
            int it = 0;
            for (int j = bytes.Length - 1; (carry != 0 || it < length) && j >= 0; j--, it++)
            {
                carry += 58 * bytes[j];
                bytes[j] = (byte)(carry & 0xFF);
                carry >>= 8;
            }
            length = it;
        }

        // 跳过缓冲区前导 0
        int start = bytes.Length - length;
        while (start < bytes.Length && bytes[start] == 0) start++;

        var result = new byte[zeros + (bytes.Length - start)];
        for (int i = 0; i < zeros; i++) result[i] = 0;
        Buffer.BlockCopy(bytes, start, result, zeros, bytes.Length - start);
        return result;
    }

    /// <summary>将 Base58 字符串解码为 UTF-8 字符串。</summary>
    public static string DecodeToString(string base58)
        => System.Text.Encoding.UTF8.GetString(Decode(base58));

    private static int[] BuildIndexMap(string alphabet)
    {
        var map = new int[256];
        for (int i = 0; i < 256; i++) map[i] = -1;
        for (int i = 0; i < alphabet.Length; i++) map[alphabet[i]] = i;
        return map;
    }
}
