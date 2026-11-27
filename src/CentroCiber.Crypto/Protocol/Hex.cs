namespace CentroCiber.Crypto.Protocol;

/// <summary>Codificación hexadecimal según el estándar (§3).</summary>
public static class Hex
{
    /// <summary>Hex minúsculas (hash de contenido, digestHex, macHex).</summary>
    public static string Lower(ReadOnlySpan<byte> data) => Convert.ToHexStringLower(data);

    /// <summary>Hex MAYÚSCULAS (huellas de certificado, SHA8 del nombre de zip).</summary>
    public static string Upper(ReadOnlySpan<byte> data) => Convert.ToHexString(data);

    public static bool TryDecode(string? value, out byte[] bytes)
    {
        bytes = [];
        if (string.IsNullOrEmpty(value) || value.Length % 2 != 0)
        {
            return false;
        }

        try
        {
            bytes = Convert.FromHexString(value);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
