using System.Globalization;

namespace CentroCiber.MockNode;

/// <summary>
/// Herramienta: <c>dotnet run --project tools/CentroCiber.MockNode -- [--port 5001] [--team 1] [--bind 0.0.0.0] [--async]</c>
/// </summary>
internal static class MockNodeProgram
{
    public static async Task Main(string[] args)
    {
        var options = new MockNodeOptions
        {
            Port = int.Parse(Arg(args, "--port") ?? "5001", CultureInfo.InvariantCulture),
            TeamNumber = int.Parse(Arg(args, "--team") ?? "1", CultureInfo.InvariantCulture),
            BindAddress = Arg(args, "--bind") ?? "127.0.0.1",
            AlwaysAsync = args.Contains("--async"),
        };
        await using var node = await MockNodeHost.StartAsync(options);
        Console.WriteLine($"MockNode {node.NodeId} (AESGCM) en http://{options.BindAddress}:{node.Port}");
        Console.WriteLine($"Huella: {node.Identity.Thumbprint}");
        Console.WriteLine("Ctrl+C para detener.");
        var done = new TaskCompletionSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            done.TrySetResult();
        };
        await done.Task;
    }

    private static string? Arg(string[] args, string name)
    {
        var i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }
}
