using System.Text;
using CentroCiber.Crypto.Protocol;

namespace CentroCiber.Web.Api;

/// <summary>Tipo de vista previa de un contenido recibido.</summary>
public enum PreviewType
{
    Text,
    Image,
    Binary,
}

/// <summary>
/// Decide cómo mostrar un contenido ajeno en el navegador. Solo se muestran en línea texto plano e imágenes
/// rasterizadas (PNG, JPEG, GIF, BMP) detectadas por sus bytes; nunca HTML ni SVG, para evitar XSS con
/// contenido de otros nodos.
/// </summary>
public static class PreviewKind
{
    public const int MaxTextPreviewBytes = 200 * 1024;

    public static (PreviewType Type, string Mime) Detect(ReadOnlySpan<byte> data, string? contentType, string? payloadMode, string? fileName)
    {
        if (ImageMime(data) is { } image)
        {
            return (PreviewType.Image, image);
        }

        var ext = Path.GetExtension(fileName ?? string.Empty).ToUpperInvariant();
        var declaredText = payloadMode == ProtocolConstants.PayloadText
            || (contentType?.StartsWith("text/", StringComparison.OrdinalIgnoreCase) ?? false)
            || contentType is "application/json"
            || ext is ".TXT" or ".JSON" or ".CSV" or ".MD" or ".LOG" or ".XML";
        if ((declaredText || LooksLikeText(data)) && IsUtf8(data))
        {
            return (PreviewType.Text, "text/plain; charset=utf-8");
        }

        return (PreviewType.Binary, "application/octet-stream");
    }

    /// <summary>Tipo MIME por firma de bytes; nulo si no es una imagen segura de mostrar.</summary>
    public static string? ImageMime(ReadOnlySpan<byte> d) =>
        d.Length >= 8 && d[..8].SequenceEqual(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }) ? "image/png"
        : d.Length >= 3 && d[0] == 0xFF && d[1] == 0xD8 && d[2] == 0xFF ? "image/jpeg"
        : d.Length >= 6 && (d[..6].SequenceEqual("GIF87a"u8) || d[..6].SequenceEqual("GIF89a"u8)) ? "image/gif"
        : d.Length >= 2 && d[0] == (byte)'B' && d[1] == (byte)'M' ? "image/bmp"
        : null;

    public static string TextPreview(byte[] data) =>
        Encoding.UTF8.GetString(data, 0, Math.Min(data.Length, MaxTextPreviewBytes))
        + (data.Length > MaxTextPreviewBytes ? "\n… (vista previa recortada)" : string.Empty);

    private static bool IsUtf8(ReadOnlySpan<byte> data)
    {
        var sample = data[..Math.Min(data.Length, MaxTextPreviewBytes)];
        try
        {
            _ = new UTF8Encoding(false, true).GetCharCount(sample);
            return true;
        }
        catch (DecoderFallbackException)
        {
            // Puede cortarse a la mitad de un carácter multibyte al recortar; se tolera solo en el borde.
            return sample.Length == MaxTextPreviewBytes;
        }
    }

    private static bool LooksLikeText(ReadOnlySpan<byte> data)
    {
        var sample = data[..Math.Min(data.Length, 4096)];
        if (sample.Length == 0)
        {
            return true;
        }

        var control = 0;
        foreach (var b in sample)
        {
            if (b < 0x09 || (b > 0x0D && b < 0x20))
            {
                control++;
            }
        }

        return control * 100 / sample.Length < 2;
    }
}
