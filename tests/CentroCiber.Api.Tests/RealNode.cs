using System.Net;
using System.Net.Sockets;
using CentroCiber.Web.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;

namespace CentroCiber.Api.Tests;

/// <summary>Nodo EQ08 real (Kestrel en puertos libres) para pruebas de red: HTTPS, UDP y nodo a nodo.</summary>
public sealed class RealNode : IAsyncDisposable
{
    private RealNode(WebApplication app, string dataPath, int httpPort, int httpsPort)
    {
        App = app;
        DataPath = dataPath;
        HttpPort = httpPort;
        HttpsPort = httpsPort;
    }

    public WebApplication App { get; }

    public string DataPath { get; }

    public int HttpPort { get; }

    public int HttpsPort { get; }

    public IServiceProvider Services => App.Services;

    public Uri HttpBase => new($"http://127.0.0.1:{HttpPort}");

    public static int FreeTcpPort()
    {
        using var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        return ((IPEndPoint)l.LocalEndpoint).Port;
    }

    public static int FreeUdpPort()
    {
        using var u = new UdpClient(0);
        return ((IPEndPoint)u.Client.LocalEndPoint!).Port;
    }

    public static async Task<RealNode> StartAsync(int teamNumber = 8, Dictionary<string, string?>? extra = null)
    {
        var dataPath = Path.Combine(Path.GetTempPath(), "cc-real", Guid.NewGuid().ToString("N"));
        var http = FreeTcpPort();
        var https = FreeTcpPort();
        var settings = new Dictionary<string, string?>
        {
            ["Node:TeamNumber"] = teamNumber.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["Node:HttpPort"] = http.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["Node:HttpsPort"] = https.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["Node:DataPath"] = dataPath,
            ["Node:EnableUi"] = "false",
            ["Node:AdvertisedIp"] = "127.0.0.1",
            ["Node:Discovery:Enabled"] = "false",
            ["PFX_PASSWORD"] = "prueba-local",
            ["Logging:LogLevel:Default"] = "Warning",
        };
        foreach (var kv in extra ?? [])
        {
            settings[kv.Key] = kv.Value;
        }

        var app = NodeHost.Build([], b => b.Configuration.AddInMemoryCollection(settings));
        await app.StartAsync();
        return new RealNode(app, dataPath, http, https);
    }

    public async ValueTask DisposeAsync()
    {
        await App.StopAsync();
        await App.DisposeAsync();
        try
        {
            Directory.Delete(DataPath, true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
