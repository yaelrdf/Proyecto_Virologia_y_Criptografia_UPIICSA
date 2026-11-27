using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using CentroCiber.Crypto.Identity;
using CentroCiber.Crypto.Protocol;

namespace CentroCiber.Crypto.Envelope;

/// <summary>Resultado de sellar: el sobre y el texto cifrado (para <c>resultado.enc</c>).</summary>
public sealed record SealedEnvelope(CcEnvelope Envelope, byte[] Ciphertext);

/// <summary>
/// Implementación de <c>CC-ENV-1</c>: CEK aleatoria de 32 bytes, AES-256-GCM (nonce 12, tag 16,
/// AAD = UTF-8 del requestId o packetId) y RSA-OAEP-SHA256 para envolver la CEK.
/// </summary>
public static class EnvelopeCrypto
{
    /// <summary>Sella <paramref name="plaintext"/> para el certificado del destinatario.</summary>
    public static SealedEnvelope Seal(ReadOnlySpan<byte> plaintext, X509Certificate2 recipientCertificate,
        string recipientNode, string aadId, bool includeCiphertext = true)
    {
        var cek = RandomNumberGenerator.GetBytes(ProtocolConstants.EnvelopeKeyBytes);
        var nonce = RandomNumberGenerator.GetBytes(ProtocolConstants.EnvelopeNonceBytes);
        var tag = new byte[ProtocolConstants.EnvelopeTagBytes];
        var ciphertext = new byte[plaintext.Length];
        try
        {
            using (var aes = new AesGcm(cek, ProtocolConstants.EnvelopeTagBytes))
            {
                aes.Encrypt(nonce, plaintext, ciphertext, tag, Encoding.UTF8.GetBytes(aadId));
            }

            using var rsa = recipientCertificate.GetRSAPublicKey()
                ?? throw new ProtocolException(ErrorCodes.Cert, "El certificado del destinatario no tiene llave RSA.");
            var wrapped = rsa.Encrypt(cek, RSAEncryptionPadding.OaepSHA256);
            var envelope = new CcEnvelope
            {
                Envelope = ProtocolConstants.EnvelopeName,
                RecipientNode = recipientNode,
                RecipientThumbprintSha256 = CertificateTools.Thumbprint(recipientCertificate),
                WrappedKeyBase64 = Convert.ToBase64String(wrapped),
                NonceBase64 = Convert.ToBase64String(nonce),
                TagBase64 = Convert.ToBase64String(tag),
                CiphertextBase64 = includeCiphertext ? Convert.ToBase64String(ciphertext) : null,
            };
            return new SealedEnvelope(envelope, ciphertext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cek);
        }
    }

    /// <summary>
    /// Abre un sobre dirigido a <paramref name="identity"/> usando <c>ciphertextBase64</c>.
    /// El llamador DEBE borrar el resultado con <c>ZeroMemory</c> si es secreto.
    /// </summary>
    public static byte[] Open(CcEnvelope envelope, NodeIdentity identity, string aadId) =>
        OpenCore(envelope, identity, aadId, null);

    /// <summary>Abre un sobre cuyo texto cifrado viaja aparte (<c>resultado.enc</c> + <c>resultEnvelope</c>).</summary>
    public static byte[] OpenDetached(CcEnvelope envelope, byte[] ciphertext, NodeIdentity identity, string aadId) =>
        OpenCore(envelope, identity, aadId, ciphertext);

    private static byte[] OpenCore(CcEnvelope envelope, NodeIdentity identity, string aadId, byte[]? detached)
    {
        if (!string.Equals(envelope.Envelope, ProtocolConstants.EnvelopeName, StringComparison.Ordinal))
        {
            throw new ProtocolException(ErrorCodes.EnvDecrypt, "Tipo de sobre no soportado.");
        }

        // §8.3: rechazar si la huella no es la propia.
        if (!string.Equals(envelope.RecipientThumbprintSha256, identity.Thumbprint, StringComparison.Ordinal)
            || !string.Equals(envelope.RecipientNode, identity.NodeId, StringComparison.Ordinal))
        {
            throw new ProtocolException(ErrorCodes.EnvRecipient, "El sobre no está dirigido a este nodo.");
        }

        byte[]? cek = null;
        try
        {
            var wrapped = Convert.FromBase64String(envelope.WrappedKeyBase64);
            var nonce = Convert.FromBase64String(envelope.NonceBase64);
            var tag = Convert.FromBase64String(envelope.TagBase64);
            var ciphertext = detached
                ?? Convert.FromBase64String(envelope.CiphertextBase64
                    ?? throw new ProtocolException(ErrorCodes.EnvDecrypt, "El sobre no trae ciphertextBase64."));
            if (nonce.Length != ProtocolConstants.EnvelopeNonceBytes || tag.Length != ProtocolConstants.EnvelopeTagBytes)
            {
                throw new ProtocolException(ErrorCodes.EnvDecrypt, "Nonce o etiqueta con longitud inválida.");
            }

            cek = identity.PrivateKey.Decrypt(wrapped, RSAEncryptionPadding.OaepSHA256);
            if (cek.Length != ProtocolConstants.EnvelopeKeyBytes)
            {
                throw new ProtocolException(ErrorCodes.EnvDecrypt, "La clave del sobre no mide 32 bytes.");
            }

            var plaintext = new byte[ciphertext.Length];
            using var aes = new AesGcm(cek, ProtocolConstants.EnvelopeTagBytes);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, Encoding.UTF8.GetBytes(aadId));
            return plaintext;
        }
        catch (FormatException ex)
        {
            throw new ProtocolException(ErrorCodes.EnvDecrypt, "El sobre tiene Base64 inválido.", ex);
        }
        catch (CryptographicException ex)
        {
            throw new ProtocolException(ErrorCodes.EnvDecrypt, "El sobre no se pudo abrir.", ex);
        }
        finally
        {
            if (cek is not null)
            {
                CryptographicOperations.ZeroMemory(cek);
            }
        }
    }

    /// <summary>Sella un diccionario de secretos (todos cadenas) como JSON UTF-8 (§8.3).</summary>
    public static CcEnvelope SealSecrets(IReadOnlyDictionary<string, string> secrets, X509Certificate2 recipientCertificate,
        string recipientNode, string requestId)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(secrets);
        try
        {
            return Seal(json, recipientCertificate, recipientNode, requestId).Envelope;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(json);
        }
    }

    /// <summary>Abre un sobre de secretos y devuelve el diccionario de cadenas.</summary>
    public static Dictionary<string, string> OpenSecrets(CcEnvelope envelope, NodeIdentity identity, string requestId)
    {
        var plain = Open(envelope, identity, requestId);
        try
        {
            using var doc = JsonDocument.Parse(plain);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new ProtocolException(ErrorCodes.Params, "Los secretos deben ser un objeto JSON.");
            }

            var result = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var p in doc.RootElement.EnumerateObject())
            {
                if (p.Value.ValueKind != JsonValueKind.String)
                {
                    throw new ProtocolException(ErrorCodes.Params, $"El secreto {p.Name} debe ser una cadena.");
                }

                result[p.Name] = p.Value.GetString()!;
            }

            return result;
        }
        catch (JsonException ex)
        {
            throw new ProtocolException(ErrorCodes.EnvDecrypt, "Los secretos del sobre no son JSON válido.", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }
}
