using Tomlyn;
using Tomlyn.Model;
using Tomlyn.Serialization;

namespace ServiceLib.Tests.CoreConfig;

public class TrustTunnelConfigTests
{
    [Test]
    public async Task LaunchConfig_ReplacesListenerAndPreservesStealthSettings()
    {
        const string source = """
            vpn_mode = "general"
            loglevel = "error"

            [endpoint]
            hostname = "vpn.example.com"
            custom_sni = "sni.example.com"
            addresses = ["192.0.2.1:443", "[2001:db8::1]:443"]
            username = "demo"
            password = "demo-password"
            client_random = "beef/ffff"
            client_random_auth_key = "deadbeef"
            tls_profile = "chrome"
            upstream_protocol = "http3"

            [listener.tun]
            included_routes = ["0.0.0.0/0"]
            """;

        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, source);
            var context = CreateContext(path);
            var launch = await CoreConfigHandler.GenerateClientConfig(context with { TrustTunnelSocksPort = 29876 }, null);

            await launch.Success.Should().BeTrue();
            var model = TomlSerializer.Deserialize((string)launch.Data!, TrustTunnelTestTomlContext.Default.TomlTable)!;
            await ((string)model["loglevel"]!).Should().BeEqualTo("info");
            var endpoint = (TomlTable)model["endpoint"]!;
            await ((string)endpoint["client_random"]!).Should().BeEqualTo("beef/ffff");
            await ((string)endpoint["client_random_auth_key"]!).Should().BeEqualTo("deadbeef");
            await ((string)endpoint["custom_sni"]!).Should().BeEqualTo("sni.example.com");
            await ((string)endpoint["tls_profile"]!).Should().BeEqualTo("chrome");
            await ((string)endpoint["upstream_protocol"]!).Should().BeEqualTo("http3");
            await ((TomlArray)endpoint["addresses"]!).Count.Should().BeEqualTo(2);

            var listener = (TomlTable)model["listener"]!;
            await listener.ContainsKey("tun").Should().BeFalse();
            var socks = (TomlTable)listener["socks"]!;
            await ((string)socks["address"]!).Should().BeEqualTo("127.0.0.1:29876");

            var export = await CoreConfigHandler.GenerateClientConfig(context, null);
            await ((string)export.Data!).Should().BeEqualTo(source);
            await (await File.ReadAllTextAsync(path)).Should().BeEqualTo(source);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Test]
    public async Task LaunchConfig_RejectsMalformedToml()
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, "[endpoint\n");
            var result = await CoreConfigHandler.GenerateClientConfig(CreateContext(path), null);

            await result.Success.Should().BeFalse();
            await (result.Msg?.Contains("invalid TOML", StringComparison.Ordinal) == true).Should().BeTrue();
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static CoreConfigContext CreateContext(string path) => new()
    {
        Node = new ProfileItem { ConfigType = EConfigType.Custom, CoreType = ECoreType.TrustTunnel, Address = path },
        RunCoreType = ECoreType.TrustTunnel,
    };
}

[TomlSerializable(typeof(TomlTable))]
internal partial class TrustTunnelTestTomlContext : TomlSerializerContext
{
}
