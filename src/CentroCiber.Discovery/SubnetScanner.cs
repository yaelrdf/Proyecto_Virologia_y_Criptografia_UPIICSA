using System.Net;
using System.Text.Json;
using CentroCiber.Crypto.Protocol;

namespace CentroCiber.Discovery;

/// <summary>Nodo que respondió al escaneo.</summary>
public sealed record ScanHit(IPAddress Address, int Port, string NodeId, string StatusJson);

/// <summary>
/// Escaneo HTTP de respaldo (§6.2): recorre la subred /24 en los puertos 5001–5020 con
/// <c>GET /api/status</c>, 500 ms por intento y 64 conexiones en paralelo como máximo.
/// </summary>
public sealed class SubnetScanner(HttpClient http)
{
    private readonly Lock gate = new();
    private DateTimeOffset? lastAutomatic;

    public TimeSpan AttemptTimeout { get; init; } = ProtocolConstants.ScanAttemptTimeout;

    /// <summary>Hosts .1–.254 de la /24 de <paramref name="address"/>.</summary>
    public static IEnumerable<IPAddress> Slash24(IPAddress address)
    {
        var b = address.GetAddressBytes();
        for (var i = 1; i <= 254; i++)
        {
            yield return new IPAddress([b[0], b[1], b[2], (byte)i]);
        }
    }

    /// <summary>§6.2: un ciclo automático no debe repetirse antes de 5 min. Los escaneos manuales no se limitan.</summary>
    public bool TryBeginAutomatic(DateTimeOffset now)
    {
        lock (gate)
        {
            if (lastAutomatic is { } last && now - last < ProtocolConstants.ScanMinAutomaticInterval)
            {
                return false;
            }

            lastAutomatic = now;
            return true;
        }
    }

    public async Task<IReadOnlyList<ScanHit>> ScanAsync(IEnumerable<IPAddress> hosts, int portFrom, int portTo, CancellationToken ct)
    {
        var targets = hosts.SelectMany(h => Enumerable.Range(portFrom, portTo - portFrom + 1).Select(p => (h, p))).ToList();
        var hits = new System.Collections.Concurrent.ConcurrentBag<ScanHit>();
        await Parallel.ForEachAsync(targets, new ParallelOptions
        {
            MaxDegreeOfParallelism = ProtocolConstants.ScanMaxParallelism,
            CancellationToken = ct,
        }, async (t, token) =>
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
            cts.CancelAfter(AttemptTimeout);
            try
            {
                var url = new Uri($"http://{t.h}:{t.p}/api/status");
                using var response = await http.GetAsync(url, cts.Token);
                if (!response.IsSuccessStatusCode)
                {
                    return;
                }

                var json = await response.Content.ReadAsStringAsync(cts.Token);
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("nodeId", out var id) && Identifiers.IsNodeId(id.GetString()))
                {
                    hits.Add(new ScanHit(t.h, t.p, id.GetString()!, json));
                }
            }
            catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or JsonException or InvalidOperationException)
            {
                // Sin respuesta en 500 ms o respuesta no válida: se ignora.
            }
        });
        return hits.OrderBy(h => h.NodeId, StringComparer.Ordinal).ToList();
    }
}
