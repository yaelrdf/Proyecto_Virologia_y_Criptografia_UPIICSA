using System.Diagnostics;

namespace CentroCiber.Packaging.Tests;

/// <summary>Ejecuta el intérprete de Python que tenga instalada la librería cryptography.</summary>
public static class PythonRunner
{
    private static readonly Lazy<string> Interpreter = new(Find);

    public static string Executable => Interpreter.Value;

    public static (int ExitCode, string Output) Run(IEnumerable<string> args, IDictionary<string, string>? env = null, string? workingDirectory = null)
    {
        var psi = new ProcessStartInfo(Executable)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            WorkingDirectory = workingDirectory ?? RepoPaths.Root,
        };
        foreach (var a in args)
        {
            psi.ArgumentList.Add(a);
        }

        psi.Environment["PYTHONIOENCODING"] = "utf-8";
        foreach (var kv in env ?? new Dictionary<string, string>())
        {
            psi.Environment[kv.Key] = kv.Value;
        }

        using var p = Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(TimeSpan.FromMinutes(3)))
        {
            p.Kill(entireProcessTree: true);
            throw new TimeoutException("Python no terminó en 3 minutos.");
        }

        return (p.ExitCode, stdout.Result + stderr.Result);
    }

    private static string Find()
    {
        foreach (var candidate in new[] { "python3", "python" })
        {
            try
            {
                using var p = Process.Start(new ProcessStartInfo(candidate, "-c \"import cryptography, pytest\"")
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                })!;
                p.WaitForExit(TimeSpan.FromSeconds(30));
                if (p.ExitCode == 0)
                {
                    return candidate;
                }
            }
            catch (System.ComponentModel.Win32Exception)
            {
                // No existe este intérprete; probar el siguiente.
            }
        }

        throw new InvalidOperationException(
            "Las pruebas de interoperabilidad requieren Python 3 con 'cryptography' y 'pytest': " +
            "python -m pip install -r tests/interop/requirements.txt");
    }
}
