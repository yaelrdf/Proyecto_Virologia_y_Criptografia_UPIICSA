using System.Globalization;
using System.Net;
using CentroCiber.Crypto.Identity;
using CentroCiber.Infrastructure.Configuration;
using CentroCiber.Infrastructure.Network;
using CentroCiber.Infrastructure.Storage;

namespace CentroCiber.Application;

/// <summary>Estado del nodo en ejecución: identidad, opciones, rutas y reloj.</summary>
public sealed class NodeContext
{
    private readonly Lock gate = new();
    private NodeIdentity identity;

    public NodeContext(NodeOptions options, NodeIdentity identity, string dataPath, bool httpsActive, TimeProvider clock)
    {
        Options = options;
        this.identity = identity;
        DataPath = dataPath;
        HttpsActive = httpsActive;
        Clock = clock;
        Store = new PackageStore(Path.Combine(dataPath, options.StorageFolder));
    }

    public NodeOptions Options { get; }

    public string DataPath { get; }

    public bool HttpsActive { get; }

    public TimeProvider Clock { get; }

    public PackageStore Store { get; }

    public NodeIdentity Identity
    {
        get
        {
            lock (gate)
            {
                return identity;
            }
        }
    }

    public string NodeId => Options.NodeId;

    public int TeamNumber => Options.TeamNumber;

    public int HttpPort => Options.EffectiveHttpPort;

    public int? HttpsPort => HttpsActive ? Options.EffectiveHttpsPort : null;

    public string PfxPath => Path.Combine(DataPath, Options.PfxFileName);

    /// <summary>IP anunciada (opción <c>AdvertisedIp</c> o la de la ruta por defecto).</summary>
    public IPAddress AdvertisedAddress =>
        !string.IsNullOrWhiteSpace(Options.AdvertisedIp) && IPAddress.TryParse(Options.AdvertisedIp, out var ip)
            ? ip
            : NetworkInfo.PrimaryAddress();

    /// <summary><c>sourceIp</c> del manifiesto: <c>IP:puerto</c>.</summary>
    public string SourceIp => string.Create(CultureInfo.InvariantCulture, $"{AdvertisedAddress}:{HttpPort}");

    /// <summary>Regenera el certificado (cambia la huella, §7). HTTPS lo toma al reiniciar.</summary>
    public NodeIdentity RegenerateIdentity(string password)
    {
        var fresh = NodeIdentity.Create(TeamNumber, Clock);
        fresh.SavePfx(PfxPath, password);
        lock (gate)
        {
            identity = fresh;
        }

        return fresh;
    }
}
