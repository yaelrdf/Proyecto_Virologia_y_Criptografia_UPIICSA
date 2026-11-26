using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace CentroCiber.Api.Tests;

/// <summary>Nodo EQ08 en memoria con carpeta de datos temporal.</summary>
public class NodeFactory : WebApplicationFactory<Program>
{
    private readonly Dictionary<string, string?> settings;

    public NodeFactory(Dictionary<string, string?>? extra = null)
    {
        DataPath = Path.Combine(Path.GetTempPath(), "cc-tests", Guid.NewGuid().ToString("N"));
        settings = new Dictionary<string, string?>
        {
            ["Node:DataPath"] = DataPath,
            ["Node:EnableUi"] = "false",
            ["Node:Discovery:Enabled"] = "false",
            ["PFX_PASSWORD"] = "prueba-local",
        };
        foreach (var kv in extra ?? [])
        {
            settings[kv.Key] = kv.Value;
        }
    }

    public string DataPath { get; }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        foreach (var kv in settings)
        {
            builder.UseSetting(kv.Key, kv.Value);
        }
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        try
        {
            Directory.Delete(DataPath, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
