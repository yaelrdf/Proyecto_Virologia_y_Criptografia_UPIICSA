namespace CentroCiber.Packaging.Tests;

/// <summary>Ubicación de la raíz del repositorio (donde está CentroCiber.slnx).</summary>
public static class RepoPaths
{
    public static string Root { get; } = FindRoot();

    private static string FindRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "CentroCiber.slnx")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new InvalidOperationException("No se encontró CentroCiber.slnx.");
    }
}
