using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CentroCiber.Crypto.Identity;
using CentroCiber.Crypto.Protocol;

namespace CentroCiber.Crypto.Envelope;

/// <summary>
/// Apertura tolerante de resultados de otros nodos (ADR 0017). Sigue §8.3 y además acepta tres variantes
/// observadas en la red, sin debilitar la criptografía (AES-256-GCM y RSA-OAEP-SHA256 se siguen exigiendo):
/// <list type="number">
/// <item>el sobre <c>CC-ENV-1</c> completo, con <c>ciphertextBase64</c>, dentro de <c>resultado.enc</c> (EQ01);</item>
/// <item>la etiqueta GCM pegada al final del texto cifrado cuando no viene <c>tagBase64</c>;</item>
/// <item>AAD distinto del <c>packetId</c> del resultado: se prueban, en orden, los candidatos que da el llamador.</item>
/// </list>
/// </summary>
public static class ResultEnvelopeOpener
{
    /// <summary>¿<paramref name="data"/> es un JSON con un sobre completo (llave envuelta y texto cifrado)?</summary>
    public static bool TryParseEnvelopeInData(byte[] data, out EnvelopeFields fields)
    {
        fields = default;
        if (data.Length < 2 || data[0] != (byte)'{')
        {
            return false;
        }

        try
        {
            using var doc = JsonDocument.Parse(data);
            var f = EnvelopeFields.From(doc.RootElement);
            if (f.WrappedKeyBase64 is null || f.CiphertextBase64 is null)
            {
                return false;
            }

            fields = f;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>
    /// Abre el resultado: primero el sobre dentro de <paramref name="resultData"/> (si lo hay); si no, el
    /// <paramref name="manifestEnvelope"/> con <paramref name="resultData"/> como texto cifrado.
    /// </summary>
    public static byte[] Open(CcEnvelope? manifestEnvelope, byte[] resultData, NodeIdentity identity, IEnumerable<string?> aadCandidates)
    {
        EnvelopeFields fields;
        byte[] ciphertext;
        if (TryParseEnvelopeInData(resultData, out var inData))
        {
            fields = inData;
            ciphertext = Decode(inData.CiphertextBase64!);
        }
        else if (manifestEnvelope is not null)
        {
            fields = EnvelopeFields.From(manifestEnvelope);
            ciphertext = resultData;
        }
        else
        {
            throw new ProtocolException(ErrorCodes.Manifest, "El resultado no trae resultEnvelope ni un sobre CC-ENV-1 en resultado.enc.");
        }

        if (fields.Envelope is { } name && !name.Equals(ProtocolConstants.EnvelopeName, StringComparison.OrdinalIgnoreCase))
        {
            throw new ProtocolException(ErrorCodes.EnvDecrypt, $"Tipo de sobre no soportado: {name}.");
        }

        if ((fields.RecipientThumbprint is { } thumb && !thumb.Equals(identity.Thumbprint, StringComparison.OrdinalIgnoreCase))
            || (fields.RecipientNode is { } node && !node.Equals(identity.NodeId, StringComparison.OrdinalIgnoreCase)))
        {
            throw new ProtocolException(ErrorCodes.EnvRecipient, "El sobre del resultado no está dirigido a este nodo.");
        }

        var nonce = Decode(fields.NonceBase64 ?? throw new ProtocolException(ErrorCodes.EnvDecrypt, "El sobre no trae nonceBase64."));
        byte[] tag;
        if (fields.TagBase64 is { } tagText)
        {
            tag = Decode(tagText);
        }
        else
        {
            if (ciphertext.Length < ProtocolConstants.EnvelopeTagBytes)
            {
                throw new ProtocolException(ErrorCodes.EnvDecrypt, "Texto cifrado demasiado corto.");
            }

            // Etiqueta pegada al final (como lo hacen Java, Python y WebCrypto).
            tag = ciphertext[^ProtocolConstants.EnvelopeTagBytes..];
            ciphertext = ciphertext[..^ProtocolConstants.EnvelopeTagBytes];
        }

        if (nonce.Length != ProtocolConstants.EnvelopeNonceBytes || tag.Length != ProtocolConstants.EnvelopeTagBytes)
        {
            throw new ProtocolException(ErrorCodes.EnvDecrypt, "Nonce o etiqueta con longitud inválida.");
        }

        byte[]? cek = null;
        try
        {
            cek = identity.PrivateKey.Decrypt(Decode(fields.WrappedKeyBase64
                ?? throw new ProtocolException(ErrorCodes.EnvDecrypt, "El sobre no trae wrappedKeyBase64.")), RSAEncryptionPadding.OaepSHA256);
            if (cek.Length != ProtocolConstants.EnvelopeKeyBytes)
            {
                throw new ProtocolException(ErrorCodes.EnvDecrypt, "La clave del sobre no mide 32 bytes.");
            }

            using var aes = new AesGcm(cek, ProtocolConstants.EnvelopeTagBytes);
            var plaintext = new byte[ciphertext.Length];
            foreach (var aad in aadCandidates.Where(a => !string.IsNullOrEmpty(a)).Distinct(StringComparer.Ordinal))
            {
                try
                {
                    aes.Decrypt(nonce, ciphertext, tag, plaintext, Encoding.UTF8.GetBytes(aad!));
                    return plaintext;
                }
                catch (AuthenticationTagMismatchException)
                {
                    // Probar el siguiente AAD candidato.
                }
            }

            throw new ProtocolException(ErrorCodes.EnvDecrypt, "El resultado no se pudo abrir con ningún AAD esperado (packetId del resultado, requestId o packetId de origen).");
        }
        catch (CryptographicException ex)
        {
            throw new ProtocolException(ErrorCodes.EnvDecrypt, "El sobre del resultado no se pudo abrir.", ex);
        }
        finally
        {
            if (cek is not null)
            {
                CryptographicOperations.ZeroMemory(cek);
            }
        }
    }

    private static byte[] Decode(string base64)
    {
        try
        {
            return Convert.FromBase64String(base64);
        }
        catch (FormatException ex)
        {
            throw new ProtocolException(ErrorCodes.EnvDecrypt, "El sobre tiene Base64 inválido.", ex);
        }
    }
}

/// <summary>Campos de un sobre <c>CC-ENV-1</c> con nombres del estándar; cualquiera puede faltar.</summary>
public readonly record struct EnvelopeFields(
    string? Envelope,
    string? RecipientNode,
    string? RecipientThumbprint,
    string? WrappedKeyBase64,
    string? NonceBase64,
    string? TagBase64,
    string? CiphertextBase64)
{
    public static EnvelopeFields From(CcEnvelope e) =>
        new(e.Envelope, e.RecipientNode, e.RecipientThumbprintSha256, e.WrappedKeyBase64, e.NonceBase64,
            string.IsNullOrEmpty(e.TagBase64) ? null : e.TagBase64, e.CiphertextBase64);

    public static EnvelopeFields From(JsonElement root)
    {
        string? S(string name) => root.ValueKind == JsonValueKind.Object && root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString()
            : null;

        return new(S("envelope"), S("recipientNode"), S("recipientThumbprintSha256"), S("wrappedKeyBase64"), S("nonceBase64"), S("tagBase64"), S("ciphertextBase64"));
    }
}
