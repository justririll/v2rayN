using Tomlyn;
using Tomlyn.Model;
using Tomlyn.Serialization;

namespace ServiceLib.Services.CoreConfig;

internal static class TrustTunnelConfigService
{
    internal const string ConfigFileName = "trusttunnel.toml";

    public static bool IsConfig(string text)
    {
        try
        {
            return HasEndpoint(TomlSerializer.Deserialize(text, TrustTunnelTomlContext.Default.TomlTable));
        }
        catch (TomlException)
        {
            return false;
        }
    }

    public static async Task<RetResult> GenerateClientConfig(CoreConfigContext context, string? fileName)
    {
        try
        {
            var path = context.Node.Address;
            var text = await File.ReadAllTextAsync(File.Exists(path) ? path : Utils.GetConfigPath(path));
            var model = TomlSerializer.Deserialize(text, TrustTunnelTomlContext.Default.TomlTable);
            if (!HasEndpoint(model))
            {
                return new RetResult { Msg = "TrustTunnel: the TOML file must contain an [endpoint] with a hostname and addresses." };
            }

            if (context.TrustTunnelSocksPort is { } port)
            {
                // The CLI reports successful endpoint negotiation at info level.
                if (!model!.TryGetValue("loglevel", out var logLevel) || logLevel is not ("info" or "debug" or "trace"))
                {
                    model["loglevel"] = "info";
                }
                model["listener"] = new TomlTable
                {
                    ["socks"] = new TomlTable { ["address"] = $"{Global.Loopback}:{port}" },
                };
                text = TomlSerializer.Serialize(model, TrustTunnelTomlContext.Default.TomlTable);
            }

            if (fileName.IsNotEmpty())
            {
                await WriteConfigAsync(fileName, text);
            }

            return new RetResult { Success = true, Data = text, Msg = string.Format(ResUI.SuccessfulConfiguration, "") };
        }
        catch (TomlException ex)
        {
            // Parser diagnostics can include TOML values such as credentials.
            return new RetResult { Msg = $"TrustTunnel: invalid TOML at line {ex.Line}, column {ex.Column}." };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Logging.SaveLog(nameof(TrustTunnelConfigService), ex);
            return new RetResult { Msg = $"TrustTunnel: {ResUI.FailedReadConfiguration}" };
        }
    }

    public static async Task WriteConfigAsync(string path, string text)
    {
        var options = new FileStreamOptions
        {
            Mode = FileMode.Create,
            Access = FileAccess.Write,
            Options = FileOptions.Asynchronous,
        };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        await using var writer = new StreamWriter(path, options);
        await writer.WriteAsync(text);
    }

    private static bool HasEndpoint(TomlTable? model)
    {
        return model?.TryGetValue("endpoint", out var value) == true
            && value is TomlTable endpoint
            && endpoint.TryGetValue("hostname", out var hostname) && hostname is string { Length: > 0 }
            && endpoint.TryGetValue("addresses", out var addresses) && addresses is TomlArray entries
            && entries.Any(address => address is string { Length: > 0 });
    }
}

[TomlSerializable(typeof(TomlTable))]
internal partial class TrustTunnelTomlContext : TomlSerializerContext
{
}
