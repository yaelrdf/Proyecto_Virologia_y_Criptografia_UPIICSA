using CentroCiber.Crypto.Protocol;

namespace CentroCiber.Infrastructure.Configuration;

/// <summary>
/// Configuración del nodo (sección <c>Node</c> de appsettings.json o variables de entorno
/// <c>CC_Node__*</c>). La contraseña del PFX NO vive aquí: se lee de <c>CC_PFX_PASSWORD</c>.
/// </summary>
public sealed class NodeOptions
{
    public const string SectionName = "Node";

    /// <summary>Clave de configuración de la contraseña del PFX (variable <c>CC_PFX_PASSWORD</c> o user-secrets).</summary>
    public const string PfxPasswordKey = "PFX_PASSWORD";

    public int TeamNumber { get; set; } = 8;

    /// <summary>0 = 5000 + TeamNumber.</summary>
    public int HttpPort { get; set; }

    /// <summary>0 = 5100 + TeamNumber.</summary>
    public int HttpsPort { get; set; }

    public bool HttpsEnabled { get; set; } = true;

    /// <summary>Carpeta de datos (BD, PFX, zips). Relativa a la raíz de contenido.</summary>
    public string DataPath { get; set; } = "data";

    public string PfxFileName { get; set; } = "identidad.pfx";

    public string DatabaseFileName { get; set; } = "centrociber.db";

    public string StorageFolder { get; set; } = "paquetes";

    /// <summary>IP que se anuncia en <c>sourceIp</c>; vacío = detectar.</summary>
    public string? AdvertisedIp { get; set; }

    public bool EnableUi { get; set; } = true;

    /// <summary>Si es falso, la interfaz acepta cualquier IP (solo para pruebas).</summary>
    public bool UiLanOnly { get; set; } = true;

    public double SyncTimeoutSeconds { get; set; } = ProtocolConstants.SyncOperationLimit.TotalSeconds;

    public int MaxConcurrentCryptoRequests { get; set; } = ProtocolConstants.MaxConcurrentCryptoRequests;

    public DiscoveryOptions Discovery { get; set; } = new();

    public string NodeId => ProtocolConstants.NodeIdFor(TeamNumber);

    public int EffectiveHttpPort => HttpPort > 0 ? HttpPort : ProtocolConstants.HttpPortFor(TeamNumber);

    public int EffectiveHttpsPort => HttpsPort > 0 ? HttpsPort : ProtocolConstants.HttpsPortFor(TeamNumber);

    public string ResolveDataPath(string contentRoot) =>
        Path.IsPathRooted(DataPath) ? DataPath : Path.GetFullPath(Path.Combine(contentRoot, DataPath));
}

/// <summary>Opciones del anuncio UDP y del escaneo (§6).</summary>
public sealed class DiscoveryOptions
{
    public bool Enabled { get; set; } = true;

    /// <summary>Puerto donde se escuchan anuncios (5099 por estándar).</summary>
    public int ListenPort { get; set; } = ProtocolConstants.DiscoveryUdpPort;

    /// <summary>
    /// Destinos adicionales <c>ip:puerto</c>. Vacío = <c>255.255.255.255:5099</c> y la
    /// dirección de broadcast de cada interfaz (§6.1).
    /// </summary>
    public List<string> Targets { get; set; } = [];

    public double IntervalSeconds { get; set; } = ProtocolConstants.BeaconInterval.TotalSeconds;

    /// <summary>Puertos del escaneo de respaldo (5001–5020 por estándar).</summary>
    public int ScanPortFrom { get; set; } = ProtocolConstants.ScanPortFrom;

    public int ScanPortTo { get; set; } = ProtocolConstants.ScanPortTo;
}
