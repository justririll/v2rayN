using System.Buffers.Text;
using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using Tomlyn;
using Tomlyn.Model;

namespace ServiceLib.Handler.Fmt;

internal static class TrustTunnelFmt
{
    public const string Scheme = "tt://";
    private static readonly UTF8Encoding _utf8 = new(false, true);

    // Wire tags from TrustTunnel/TrustTunnel DEEP_LINK.md.
    private enum Tag
    {
        Version = 0x00,
        Hostname = 0x01,
        Address = 0x02,
        CustomSni = 0x03,
        HasIpv6 = 0x04,
        Username = 0x05,
        Password = 0x06,
        SkipVerification = 0x07,
        Certificate = 0x08,
        UpstreamProtocol = 0x09,
        AntiDpi = 0x0A,
        ClientRandom = 0x0B,
        Name = 0x0C,
        DnsUpstreams = 0x0D,
        SubscriptionUrl = 0x0E,
        ClientRandomAuthKey = 0x0F,
    }

    public static (string Remarks, string Toml)? Resolve(string link)
    {
        try
        {
            var encoded = link.AsSpan(Scheme.Length);
            if (encoded.StartsWith("?"))
            {
                encoded = encoded[1..];
            }
            ReadOnlySpan<byte> payload = Base64Url.DecodeFromChars(encoded);
            var addresses = new TomlArray();
            var endpoint = new TomlTable { ["addresses"] = addresses, ["upstream_protocol"] = "http2" };
            while (!payload.IsEmpty)
            {
                var tag = ReadVarInt(ref payload);
                var value = ReadValue(ref payload);
                if (tag <= (ulong)Tag.ClientRandomAuthKey)
                {
                    ApplyField((Tag)tag, value, endpoint, addresses);
                }
            }

            if (!HasText(endpoint, "hostname") || addresses.Count == 0
                || !HasText(endpoint, "username") || !HasText(endpoint, "password"))
            {
                return null;
            }

            var model = new TomlTable
            {
                ["vpn_mode"] = "general",
                ["endpoint"] = endpoint,
                ["listener"] = new TomlTable
                {
                    ["socks"] = new TomlTable { ["address"] = "127.0.0.1:1080" },
                },
            };
            var remarks = HasText(endpoint, "name") ? (string)endpoint["name"]! : (string)endpoint["hostname"]!;
            return (remarks, TomlSerializer.Serialize(model, TrustTunnelTomlContext.Default.TomlTable));
        }
        catch (Exception ex) when (ex is FormatException or InvalidDataException or DecoderFallbackException
            or AsnContentException or CryptographicException or TomlException)
        {
            // A link can contain credentials, including in parser diagnostics.
            return null;
        }
    }

    private static void ApplyField(Tag tag, ReadOnlySpan<byte> value, TomlTable endpoint, TomlArray addresses)
    {
        switch (tag)
        {
            case Tag.Version:
                if (ReadVarInt(ref value) > 2 || !value.IsEmpty)
                {
                    throw new InvalidDataException();
                }
                break;
            case Tag.Hostname: endpoint["hostname"] = _utf8.GetString(value); break;
            case Tag.Address:
                var address = _utf8.GetString(value);
                if (string.IsNullOrWhiteSpace(address))
                {
                    throw new InvalidDataException();
                }
                addresses.Add(address);
                break;
            case Tag.CustomSni: endpoint["custom_sni"] = _utf8.GetString(value); break;
            case Tag.HasIpv6: endpoint["has_ipv6"] = ReadBoolean(value); break;
            case Tag.Username: endpoint["username"] = _utf8.GetString(value); break;
            case Tag.Password: endpoint["password"] = _utf8.GetString(value); break;
            case Tag.SkipVerification: endpoint["skip_verification"] = ReadBoolean(value); break;
            case Tag.Certificate: endpoint["certificate"] = ReadCertificateChain(value); break;
            case Tag.UpstreamProtocol:
                endpoint["upstream_protocol"] = value switch
                {
                    [0x01] => "http2",
                    [0x02] => "http3",
                    _ => throw new InvalidDataException(),
                };
                break;
            case Tag.AntiDpi: endpoint["anti_dpi"] = ReadBoolean(value); break;
            case Tag.ClientRandom:
                var random = _utf8.GetString(value);
                foreach (var part in random.Split('/', 2))
                {
                    _ = Convert.FromHexString(part);
                }
                endpoint["client_random"] = random;
                break;
            case Tag.Name: endpoint["name"] = _utf8.GetString(value); break;
            case Tag.DnsUpstreams:
                var dnsUpstreams = new TomlArray();
                while (!value.IsEmpty)
                {
                    dnsUpstreams.Add(_utf8.GetString(ReadValue(ref value)));
                }
                endpoint["dns_upstreams"] = dnsUpstreams;
                break;
            case Tag.SubscriptionUrl:
                // Import the embedded endpoint when one is present in a version 2 link.
                if (!_utf8.GetString(value).StartsWith(Global.HttpsProtocol, StringComparison.Ordinal))
                {
                    throw new InvalidDataException();
                }
                break;
            case Tag.ClientRandomAuthKey:
                var authKey = _utf8.GetString(value);
                _ = Convert.FromHexString(authKey);
                endpoint["client_random_auth_key"] = authKey;
                break;
        }
    }

    private static bool HasText(TomlTable table, string key) => table.TryGetValue(key, out var value) && value is string { Length: > 0 };

    private static bool ReadBoolean(ReadOnlySpan<byte> value) => value switch
    {
        [0] => false,
        [1] => true,
        _ => throw new InvalidDataException(),
    };

    private static ReadOnlySpan<byte> ReadValue(ref ReadOnlySpan<byte> payload)
    {
        var length = ReadVarInt(ref payload);
        if (length > (ulong)payload.Length)
        {
            throw new InvalidDataException();
        }
        var value = payload[..(int)length];
        payload = payload[(int)length..];
        return value;
    }

    private static ulong ReadVarInt(ref ReadOnlySpan<byte> payload)
    {
        if (payload.IsEmpty)
        {
            throw new InvalidDataException();
        }
        // RFC 9000 encodes the byte width in the first two bits.
        var width = 1 << (payload[0] >> 6);
        if (width > payload.Length)
        {
            throw new InvalidDataException();
        }
        var value = (ulong)(payload[0] & 0x3F);
        for (var i = 1; i < width; i++)
        {
            value = (value << 8) | payload[i];
        }
        payload = payload[width..];
        return value;
    }

    private static string ReadCertificateChain(ReadOnlySpan<byte> value)
    {
        var pem = new StringBuilder();
        while (!value.IsEmpty)
        {
            AsnDecoder.ReadSequence(value, AsnEncodingRules.DER, out _, out _, out var consumed);
            using var certificate = X509CertificateLoader.LoadCertificate(value[..consumed]);
            pem.AppendLine(certificate.ExportCertificatePem());
            value = value[consumed..];
        }
        return pem.ToString();
    }
}
