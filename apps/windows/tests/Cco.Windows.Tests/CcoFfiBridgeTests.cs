using System.Text.Json.Nodes;
using Cco.Windows.Core;
using Xunit;

namespace Cco.Windows.Tests;

public class CcoFfiBridgeTests
{
    [Fact]
    public void VersionAndAnalyticsMatchDissertationControlValues()
    {
        var version = CcoClient.GetVersion();
        Assert.False(string.IsNullOrWhiteSpace(version));

        // Exact control table from Chapter 3 (n=20, m=2, j=3): M1=4896, M3=6174, M4=6516
        var summary = CcoClient.RunAnalyticsSummary(20, 2, 3);
        Assert.Equal("4896", summary.F1Routes);
        Assert.Equal("6174", summary.F3Routes);
        Assert.Equal("6516", summary.F4Routes);
        Assert.Equal("23970816", summary.I2pRoutes);
        Assert.InRange(summary.F1EntropyBits, 12.257, 12.258);
        Assert.InRange(summary.F3EntropyBits, 12.591, 12.593);
        Assert.InRange(summary.F4EntropyBits, 12.669, 12.671);
        Assert.NotNull(summary.F4MonteCarloPct);
    }

    [Fact]
    public void DemoProfileTrustRegistryVerifiesAndRejectsTamperingFailClosed()
    {
        var profileJson = CcoClient.GenerateDemoProfileJson("A", "B");
        var obj = JsonNode.Parse(profileJson)!.AsObject();
        var regJson = obj["trust_registry_json"]!.GetValue<string>();
        var rootJson = obj["trust_root_json"]!.GetValue<string>();

        var status = CcoClient.VerifyTrustBundle(regJson, rootJson, ["A", "X1", "X2", "B"]);
        Assert.True(status.Authenticated);
        Assert.Equal(1UL, status.Version);
        Assert.Contains("A", status.Nodes);
        Assert.Contains("B", status.Nodes);

        var tampered = regJson.Replace("\"version\":1", "\"version\":999", StringComparison.Ordinal);
        var ex = Assert.Throws<CcoFfiException>(
            () => CcoClient.VerifyTrustBundle(tampered, rootJson, ["A", "X1", "X2", "B"]));
        Assert.False(string.IsNullOrWhiteSpace(ex.ErrorCode));
    }

    [Fact]
    public void PrepareTunnelStartConfigInjectsWindowsDefaultsAndRejectsBadMode()
    {
        var profileJson = CcoClient.GenerateDemoProfileJson("A", "B");
        var built = CcoClient.PrepareTunnelStartConfig(
            profileJson,
            "replay.sqlite",
            "window",
            x1Fanout: 3,
            x2Fanout: 2);

        var parsed = JsonNode.Parse(built)!.AsObject();
        Assert.Equal("window", parsed["mcc_mode"]!.GetValue<string>());
        Assert.Equal(3, parsed["x1_fanout"]!.GetValue<int>());
        Assert.False(parsed["has_pi_header"]!.GetValue<bool>());

        Assert.Throws<CcoFfiException>(
            () => CcoClient.PrepareTunnelStartConfig(profileJson, "replay.sqlite", "invalid-mode", 2, 2));
    }
}
