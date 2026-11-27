using CentroCiber.Web.Hosting;

var app = NodeHost.Build(args);
await app.RunAsync();

/// <summary>Punto de entrada; expuesto para <c>WebApplicationFactory</c>.</summary>
public partial class Program;
