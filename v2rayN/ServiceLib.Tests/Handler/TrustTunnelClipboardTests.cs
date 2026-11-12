using System.Buffers.Text;
using ServiceLib.Tests.CoreConfig;
using Tomlyn;
using Tomlyn.Model;

namespace ServiceLib.Tests.Handler;

public class TrustTunnelClipboardTests
{
    [Test]
    public async Task AddBatchServers_ImportsTrustTunnelEndpointAndSkipsTruncatedLink()
    {
        byte[] payload =
        [
            .. Field(0x00, [2]),
            .. Field(0x01, "vpn.example.com"),
            .. Field(0x02, "192.0.2.1:443"),
            .. Field(0x02, "[2001:db8::1]:443"),
            .. Field(0x03, "front.example.com"),
            .. Field(0x04, [0]),
            .. Field(0x05, "demo"),
            .. Field(0x06, "пароль\"\\test"),
            .. Field(0x07, [1]),
            .. Field(0x09, [2]),
            .. Field(0x0A, [1]),
            .. Field(0x0B, "beef/ffff"),
            .. Field(0x0C, "Тестовый TrustTunnel"),
            .. Field(0x0D, [13, .. "tls://1.1.1.1"u8, 13, .. "udp://8.8.8.8"u8]),
            .. Field(0x0E, "https://vpn.example.com/subscription"),
            .. Field(0x0F, new string('0', 64)),
            .. Field(0x101, "unknown tag"),
        ];
        var link = $"tt://?{Base64Url.EncodeToString(payload)}";
        var config = CoreConfigTestFactory.CreateConfig();
        SQLiteHelper.Instance.CreateTable<ProfileItem>();
        var group = $"trusttunnel-{Guid.NewGuid():N}";
        try
        {
            var imported = await ConfigHandler.AddBatchServers(config, $"tt://?AQVh\n {link} \n", group, false);
            await imported.Should().BeEqualTo(1);

            var profile = (await AppManager.Instance.ProfileItems(group))!.Single();
            await profile.ConfigType.Should().BeEqualTo(EConfigType.Custom);
            await profile.CoreType.Should().BeEqualTo(ECoreType.TrustTunnel);
            await profile.Remarks.Should().BeEqualTo("Тестовый TrustTunnel");

            var text = await File.ReadAllTextAsync(Utils.GetConfigPath(profile.Address));
            var model = TomlSerializer.Deserialize(text, TrustTunnelTestTomlContext.Default.TomlTable)!;
            var endpoint = (TomlTable)model["endpoint"]!;
            await ((string)endpoint["password"]!).Should().BeEqualTo("пароль\"\\test");
            await ((string)endpoint["custom_sni"]!).Should().BeEqualTo("front.example.com");
            await ((string)endpoint["client_random"]!).Should().BeEqualTo("beef/ffff");
            await ((string)endpoint["client_random_auth_key"]!).Should().BeEqualTo(new string('0', 64));
            await ((string)endpoint["upstream_protocol"]!).Should().BeEqualTo("http3");
            await ((bool)endpoint["has_ipv6"]!).Should().BeFalse();
            await ((bool)endpoint["skip_verification"]!).Should().BeTrue();
            await ((bool)endpoint["anti_dpi"]!).Should().BeTrue();
            await ((TomlArray)endpoint["addresses"]!).Cast<string>().Should().HaveCount(2);
            await ((TomlArray)endpoint["dns_upstreams"]!).Cast<string>().Should().HaveCount(2);
        }
        finally
        {
            foreach (var profile in await AppManager.Instance.ProfileItems(group) ?? [])
            {
                File.Delete(Utils.GetConfigPath(profile.Address));
                await SQLiteHelper.Instance.DeleteAsync(profile);
            }
        }
    }

    private static byte[] Field(int tag, string value) => Field(tag, Encoding.UTF8.GetBytes(value));

    private static byte[] Field(int tag, byte[] value) => [.. VarInt(tag), .. VarInt(value.Length), .. value];

    private static byte[] VarInt(int value) => value < 64
        ? [(byte)value]
        : [(byte)(0x40 | (value >> 8)), (byte)(value & 0xFF)];
}
