using System.Net.Security;
using System.Security.Cryptography;
using CentroCiber.Crypto.Protocol;

namespace CentroCiber.Infrastructure.Http;

/// <summary>
/// Clientes HTTP hacia otros nodos. Con HTTPS se valida que la huella del certificado TLS
/// coincida con la fijada en el directorio; no se valida cadena (certificados autofirmados, §5.2).
/// </summary>
public sealed class NodeHttpClientFactory : IDisposable
{
    // Los nodos están en la LAN: nunca se usa el proxy del sistema.
    private readonly SocketsHttpHandler plainHandler = new() { PooledConnectionLifetime = TimeSpan.FromMinutes(2), UseProxy = false };
    private readonly Dictionary<string, SocketsHttpHandler> pinnedHandlers = new(StringComparer.Ordinal);
    private readonly Lock gate = new();

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(100);

    /// <summary>Cliente HTTP simple (sin TLS): descubrimiento, escaneo y nodos sin HTTPS.</summary>
    public HttpClient CreatePlain() => new(plainHandler, disposeHandler: false) { Timeout = Timeout };

    /// <summary>Cliente HTTPS que solo acepta el certificado con <paramref name="pinnedThumbprint"/>.</summary>
    public HttpClient CreatePinned(string pinnedThumbprint)
    {
        SocketsHttpHandler handler;
        lock (gate)
        {
            if (!pinnedHandlers.TryGetValue(pinnedThumbprint, out handler!))
            {
                handler = new SocketsHttpHandler
                {
                    PooledConnectionLifetime = TimeSpan.FromMinutes(2),
                    UseProxy = false,
                    SslOptions = new SslClientAuthenticationOptions
                    {
                        RemoteCertificateValidationCallback = (_, cert, _, _) =>
                            cert is not null && string.Equals(Hex.Upper(SHA256.HashData(cert.GetRawCertData())), pinnedThumbprint, StringComparison.Ordinal),
                    },
                };
                pinnedHandlers[pinnedThumbprint] = handler;
            }
        }

        return new HttpClient(handler, disposeHandler: false) { Timeout = Timeout };
    }

    public void Dispose()
    {
        plainHandler.Dispose();
        lock (gate)
        {
            foreach (var h in pinnedHandlers.Values)
            {
                h.Dispose();
            }
        }
    }
}
