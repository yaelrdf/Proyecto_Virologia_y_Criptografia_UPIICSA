using CentroCiber.Crypto.Protocol;

namespace CentroCiber.Packaging;

/// <summary>Tipos MIME del original (campo <c>contentType</c>).</summary>
public static class ContentTypes
{
    private static readonly Dictionary<string, string> Map = new(StringComparer.OrdinalIgnoreCase)
    {
        [".txt"] = "text/plain",
        [".pdf"] = "application/pdf",
        [".png"] = "image/png",
        [".bmp"] = "image/bmp",
        [".jpg"] = "image/jpeg",
        [".jpeg"] = "image/jpeg",
        [".gif"] = "image/gif",
        [".json"] = "application/json",
        [".zip"] = "application/zip",
        [".docx"] = "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        [".csv"] = "text/csv",
        [".html"] = "text/html",
        [".bin"] = "application/octet-stream",
    };

    public static string ForFile(string fileName, string payloadMode)
    {
        if (payloadMode == ProtocolConstants.PayloadText)
        {
            return "text/plain";
        }

        return Map.TryGetValue(Path.GetExtension(fileName), out var mime) ? mime : "application/octet-stream";
    }
}
