using System.Text;
using System.Text.Json;
using CentroCiber.Crypto.Envelope;
using CentroCiber.Crypto.Identity;
using CentroCiber.Crypto.Protocol;

namespace CentroCiber.Crypto.Tests;

/// <summary>ADR 0017: apertura tolerante de resultados de otros nodos.</summary>
public sealed class ResultEnvelopeOpenerTests : IDisposable
{
    private readonly NodeIdentity me = NodeIdentity.Create(8, TimeProvider.System);
    private readonly NodeIdentity other = NodeIdentity.Create(3, TimeProvider.System);

    public void Dispose()
    {
        me.Dispose();
        other.Dispose();
    }

    [Fact] // §8.3 estándar: sobre en el manifiesto + texto cifrado aparte, AAD = packetId del resultado
    public void Standard_detached_result_opens()
    {
        var packetId = Identifiers.NewUuid();
        var s = EnvelopeCrypto.Seal("hola"u8, me.Certificate, "EQ08", packetId, includeCiphertext: false);
        ResultEnvelopeOpener.Open(s.Envelope, s.Ciphertext, me, [packetId]).ShouldBe("hola"u8.ToArray());
    }

    [Fact] // Variante: AAD = requestId en lugar del packetId del resultado
    public void Alternative_aad_candidate_is_tried()
    {
        var requestId = Identifiers.NewUuid();
        var s = EnvelopeCrypto.Seal("x"u8, me.Certificate, "EQ08", requestId, includeCiphertext: false);
        ResultEnvelopeOpener.Open(s.Envelope, s.Ciphertext, me, [Identifiers.NewUuid(), requestId]).ShouldBe("x"u8.ToArray());
        Should.Throw<ProtocolException>(() => ResultEnvelopeOpener.Open(s.Envelope, s.Ciphertext, me, [Identifiers.NewUuid()]))
            .Code.ShouldBe(ErrorCodes.EnvDecrypt);
    }

    [Fact] // Variante EQ01: sobre completo dentro de resultado.enc, con la etiqueta pegada al cifrado
    public void Envelope_in_data_with_appended_tag_opens()
    {
        var packetId = Identifiers.NewUuid();
        var s = EnvelopeCrypto.Seal("original"u8, me.Certificate, "EQ08", packetId, includeCiphertext: false);
        var data = JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, string>
        {
            ["envelope"] = "CC-ENV-1",
            ["recipientNode"] = "EQ08",
            ["wrappedKeyBase64"] = s.Envelope.WrappedKeyBase64,
            ["nonceBase64"] = s.Envelope.NonceBase64,
            ["ciphertextBase64"] = Convert.ToBase64String([.. s.Ciphertext, .. Convert.FromBase64String(s.Envelope.TagBase64)]),
        });
        ResultEnvelopeOpener.TryParseEnvelopeInData(data, out _).ShouldBeTrue();
        ResultEnvelopeOpener.Open(null, data, me, [packetId]).ShouldBe("original"u8.ToArray());
    }

    [Fact] // La tolerancia no cambia la seguridad: un sobre para otro nodo se rechaza
    public void Envelope_for_other_node_is_rejected()
    {
        var packetId = Identifiers.NewUuid();
        var s = EnvelopeCrypto.Seal("x"u8, other.Certificate, "EQ03", packetId, includeCiphertext: false);
        Should.Throw<ProtocolException>(() => ResultEnvelopeOpener.Open(s.Envelope, s.Ciphertext, me, [packetId]))
            .Code.ShouldBe(ErrorCodes.EnvRecipient);
        Should.Throw<ProtocolException>(() => ResultEnvelopeOpener.Open(null, Encoding.UTF8.GetBytes("no es sobre"), me, [packetId]))
            .Code.ShouldBe(ErrorCodes.Manifest);
    }
}
