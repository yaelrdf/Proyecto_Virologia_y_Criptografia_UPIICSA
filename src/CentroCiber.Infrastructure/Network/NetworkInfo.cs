using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace CentroCiber.Infrastructure.Network;

/// <summary>Interfaz IPv4 activa con su dirección de broadcast.</summary>
public sealed record LocalInterface(string Name, IPAddress Address, IPAddress Mask, IPAddress Broadcast);

/// <summary>Detección de IP local e interfaces (§5.3).</summary>
public static class NetworkInfo
{
    /// <summary>IP con la que se sale hacia <paramref name="target"/> (sin enviar tráfico).</summary>
    public static IPAddress LocalAddressFor(IPAddress target)
    {
        try
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            if (target.Equals(IPAddress.Broadcast))
            {
                socket.EnableBroadcast = true;
            }

            socket.Connect(target, 9);
            return (socket.LocalEndPoint as IPEndPoint)?.Address ?? IPAddress.Loopback;
        }
        catch (SocketException)
        {
            return IPAddress.Loopback;
        }
    }

    /// <summary>IP principal de la máquina (la de la ruta por defecto) o loopback.</summary>
    public static IPAddress PrimaryAddress()
    {
        var viaRoute = LocalAddressFor(IPAddress.Parse("192.0.2.1"));
        if (!IPAddress.IsLoopback(viaRoute) && !viaRoute.Equals(IPAddress.Any))
        {
            return viaRoute;
        }

        return Interfaces().Select(i => i.Address).FirstOrDefault() ?? IPAddress.Loopback;
    }

    /// <summary>Interfaces IPv4 activas que no son loopback.</summary>
    public static IReadOnlyList<LocalInterface> Interfaces()
    {
        var result = new List<LocalInterface>();
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
            {
                continue;
            }

            foreach (var ua in ni.GetIPProperties().UnicastAddresses)
            {
                if (ua.Address.AddressFamily != AddressFamily.InterNetwork || ua.IPv4Mask is null)
                {
                    continue;
                }

                result.Add(new LocalInterface(ni.Name, ua.Address, ua.IPv4Mask, Broadcast(ua.Address, ua.IPv4Mask)));
            }
        }

        return result;
    }

    public static IPAddress Broadcast(IPAddress address, IPAddress mask)
    {
        var a = address.GetAddressBytes();
        var m = mask.GetAddressBytes();
        var b = new byte[4];
        for (var i = 0; i < 4; i++)
        {
            b[i] = (byte)(a[i] | ~m[i]);
        }

        return new IPAddress(b);
    }

    /// <summary>¿Dirección privada de LAN o loopback? (10/8, 172.16/12, 192.168/16, 169.254/16, 127/8, ::1, fc00::/7, fe80::/10).</summary>
    public static bool IsPrivateOrLoopback(IPAddress? address)
    {
        if (address is null)
        {
            return false;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (IPAddress.IsLoopback(address))
        {
            return true;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var bytes6 = address.GetAddressBytes();
            return address.IsIPv6LinkLocal || (bytes6[0] & 0xFE) == 0xFC;
        }

        var b = address.GetAddressBytes();
        return b[0] == 10
            || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
            || (b[0] == 192 && b[1] == 168)
            || (b[0] == 169 && b[1] == 254);
    }
}
