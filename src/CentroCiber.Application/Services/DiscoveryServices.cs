using System.Net;
using CentroCiber.Crypto.Protocol;
using CentroCiber.Discovery;
using CentroCiber.Infrastructure.Data.Entities;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CentroCiber.Application.Services;

/// <summary>Arma el anuncio propio y procesa los ajenos (§6.1).</summary>
public sealed class DiscoveryPeer(NodeContext node, NodeDirectory directory, ILogger<DiscoveryPeer> logger) : IBeaconPeer
{
    public string OwnNodeId => node.NodeId;

    public Beacon CreateBeacon(IPAddress localAddress, string status) => new()
    {
        NodeId = node.NodeId,
        TeamNumber = node.TeamNumber,
        Ip = localAddress.ToString(),
        HttpPort = node.HttpPort,
        HttpsPort = node.HttpsPort,
        Status = status,
        Algorithms = AlgorithmCatalog.OwnedBy(node.TeamNumber).Select(a => a.Code).ToList(),
        CertificateThumbprintSha256 = node.Identity.Thumbprint,
        TimestampUtc = Identifiers.FormatTimestamp(node.Clock.GetUtcNow()),
    };

    public async Task OnBeaconAsync(Beacon beacon, IPEndPoint from, CancellationToken ct)
    {
        logger.LogDebug("Anuncio de {Node} desde {From}", beacon.NodeId, from);
        // §6.1: un anuncio no es confiable por sí mismo; ObserveAsync verifica con status y certificate.
        await directory.ObserveAsync(beacon.NodeId, beacon.Ip, beacon.HttpPort, beacon.HttpsPort, beacon.CertificateThumbprintSha256,
            beacon.Algorithms, NodeSources.Beacon, beacon.Status == ProtocolConstants.StatusOffline ? ProtocolConstants.StatusOffline : ProtocolConstants.StatusOnline, ct);
    }
}

/// <summary>Monitoreo: consulta nodos silenciosos y marca <c>offline</c> a los 90 s (§6.1).</summary>
public sealed class NodeMonitorService(NodeDirectory directory, Jobs.JobQueue jobs, ILogger<NodeMonitorService> logger) : BackgroundService
{
    public TimeSpan Period { get; init; } = TimeSpan.FromSeconds(15);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await directory.ProbeQuietNodesAsync(TimeSpan.FromSeconds(60), stoppingToken);
                await directory.MarkStaleOfflineAsync(stoppingToken);
                jobs.Purge();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "Error en el monitoreo de nodos.");
            }

            try
            {
                await Task.Delay(Period, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }
}
