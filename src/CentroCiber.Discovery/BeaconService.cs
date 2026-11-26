using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CentroCiber.Discovery;

/// <summary>Quien construye el anuncio propio y procesa los ajenos (lo implementa la capa de aplicación).</summary>
public interface IBeaconPeer
{
    string OwnNodeId { get; }

    /// <summary>Anuncio para enviar por <paramref name="localAddress"/> (la IP de la interfaz de salida, §5.3).</summary>
    Beacon CreateBeacon(IPAddress localAddress, string status);

    Task OnBeaconAsync(Beacon beacon, IPEndPoint from, CancellationToken ct);
}

/// <summary>Configuración del anuncio.</summary>
public sealed record BeaconSettings(bool Enabled, int ListenPort, IReadOnlyList<IPEndPoint> ExplicitTargets, TimeSpan Interval, IPAddress? AdvertisedAddress);

/// <summary>
/// Emisor y oyente UDP (§6.1): anuncia al iniciar y cada 30 s a <c>255.255.255.255:5099</c> y al
/// broadcast de cada interfaz; al apagarse envía <c>offline</c>. El socket usa <c>ReuseAddress</c>
/// para que varias instancias compartan el puerto (ADR 0009).
/// </summary>
public sealed class BeaconService(BeaconSettings settings, IBeaconPeer peer, ILogger<BeaconService> logger) : BackgroundService
{
    private UdpClient? socket;

    public bool Listening { get; private set; }

    public DateTimeOffset? LastSentUtc { get; private set; }

    public int BeaconsReceived { get; private set; }

    public static UdpClient CreateSocket(int port)
    {
        var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        udp.EnableBroadcast = true;
        udp.Client.Bind(new IPEndPoint(IPAddress.Any, port));
        return udp;
    }

    /// <summary>Destinos: explícitos si se configuraron; si no, broadcast global y por interfaz.</summary>
    public IReadOnlyList<(IPEndPoint Target, IPAddress Local)> Targets()
    {
        var list = new List<(IPEndPoint, IPAddress)>();
        if (settings.ExplicitTargets.Count > 0)
        {
            foreach (var t in settings.ExplicitTargets)
            {
                list.Add((t, settings.AdvertisedAddress ?? NetHelpers.LocalAddressFor(t.Address)));
            }

            return list;
        }

        var primary = settings.AdvertisedAddress ?? NetHelpers.LocalAddressFor(IPAddress.Broadcast);
        list.Add((new IPEndPoint(IPAddress.Broadcast, settings.ListenPort), primary));
        foreach (var (address, broadcast) in NetHelpers.InterfaceBroadcasts())
        {
            list.Add((new IPEndPoint(broadcast, settings.ListenPort), settings.AdvertisedAddress ?? address));
        }

        return list;
    }

    public async Task SendAsync(string status, CancellationToken ct)
    {
        if (socket is null)
        {
            return;
        }

        foreach (var (target, local) in Targets())
        {
            try
            {
                var bytes = BeaconCodec.Encode(peer.CreateBeacon(local, status));
                await socket.SendAsync(bytes, target, ct);
            }
            catch (SocketException ex)
            {
                logger.LogDebug(ex, "No se pudo enviar el anuncio a {Target}", target);
            }
        }

        LastSentUtc = DateTimeOffset.UtcNow;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!settings.Enabled)
        {
            return;
        }

        try
        {
            socket = CreateSocket(settings.ListenPort);
            Listening = true;
        }
        catch (SocketException ex)
        {
            logger.LogWarning(ex, "No se pudo abrir el puerto UDP {Port}; el descubrimiento queda deshabilitado.", settings.ListenPort);
            return;
        }

        var receiving = ReceiveLoopAsync(stoppingToken);
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                await SendAsync(Crypto.Protocol.ProtocolConstants.StatusOnline, stoppingToken);
                await Task.Delay(settings.Interval, stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
        }

        await receiving;
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(2));
            await SendAsync(Crypto.Protocol.ProtocolConstants.StatusOffline, cts.Token);
        }
        catch (OperationCanceledException)
        {
        }

        await base.StopAsync(cancellationToken);
        socket?.Dispose();
        Listening = false;
    }

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && socket is not null)
        {
            try
            {
                var result = await socket.ReceiveAsync(ct);
                var beacon = BeaconCodec.Decode(result.Buffer, peer.OwnNodeId);
                if (beacon is null)
                {
                    continue;
                }

                BeaconsReceived++;
                await peer.OnBeaconAsync(beacon, result.RemoteEndPoint, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (Exception ex) when (ex is SocketException or InvalidOperationException or HttpRequestException)
            {
                logger.LogDebug(ex, "Error al procesar un anuncio.");
            }
        }
    }
}

/// <summary>Utilidades de red mínimas (evita depender de Infrastructure, ADR 0010).</summary>
internal static class NetHelpers
{
    public static IPAddress LocalAddressFor(IPAddress target)
    {
        try
        {
            using var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { EnableBroadcast = true };
            s.Connect(target, 9);
            return (s.LocalEndPoint as IPEndPoint)?.Address ?? IPAddress.Loopback;
        }
        catch (SocketException)
        {
            return IPAddress.Loopback;
        }
    }

    public static IEnumerable<(IPAddress Address, IPAddress Broadcast)> InterfaceBroadcasts()
    {
        foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up
                || ni.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
            {
                continue;
            }

            foreach (var ua in ni.GetIPProperties().UnicastAddresses)
            {
                if (ua.Address.AddressFamily != AddressFamily.InterNetwork || ua.IPv4Mask is null)
                {
                    continue;
                }

                var a = ua.Address.GetAddressBytes();
                var m = ua.IPv4Mask.GetAddressBytes();
                var b = new byte[4];
                for (var i = 0; i < 4; i++)
                {
                    b[i] = (byte)(a[i] | ~m[i]);
                }

                yield return (ua.Address, new IPAddress(b));
            }
        }
    }
}
