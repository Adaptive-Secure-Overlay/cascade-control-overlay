using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Cco.Windows.Core;

public sealed record FfiEnvelope<T>(
    [property: JsonPropertyName("ok")] bool Ok,
    [property: JsonPropertyName("data")] T? Data,
    [property: JsonPropertyName("error")] string? Error);

public sealed record TrustStatus(
    [property: JsonPropertyName("authenticated")] bool Authenticated,
    [property: JsonPropertyName("schema")] string Schema,
    [property: JsonPropertyName("version")] ulong Version,
    [property: JsonPropertyName("signer_key_id")] string SignerKeyId,
    [property: JsonPropertyName("nodes")] List<string> Nodes,
    [property: JsonPropertyName("sha256")] string Sha256,
    [property: JsonPropertyName("recovered")] bool Recovered);

public sealed record TunnelStats(
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("overlay_handshake_tx")] ulong OverlayHandshakeTx,
    [property: JsonPropertyName("overlay_handshake_rx")] ulong OverlayHandshakeRx,
    [property: JsonPropertyName("direct_handshake_tx")] ulong DirectHandshakeTx,
    [property: JsonPropertyName("direct_handshake_rx_dropped")] ulong DirectHandshakeRxDropped,
    [property: JsonPropertyName("direct_data_tx")] ulong DirectDataTx,
    [property: JsonPropertyName("direct_data_rx")] ulong DirectDataRx,
    [property: JsonPropertyName("direct_bytes_tx")] ulong DirectBytesTx,
    [property: JsonPropertyName("direct_bytes_rx")] ulong DirectBytesRx,
    [property: JsonPropertyName("handshake_ms")] ulong? HandshakeMs,
    [property: JsonPropertyName("selected_route_hops")] byte SelectedRouteHops,
    [property: JsonPropertyName("selected_x1")] string? SelectedX1,
    [property: JsonPropertyName("mcc_mode")] string MccMode,
    [property: JsonPropertyName("trust_registry_version")] ulong TrustRegistryVersion,
    [property: JsonPropertyName("trust_registry_sha256")] string TrustRegistrySha256,
    [property: JsonPropertyName("last_error_code")] string? LastErrorCode)
{
    public bool ControlPlaneInvariantHolds => DirectHandshakeTx == 0;
}

public sealed record SanitizedEvent(
    [property: JsonPropertyName("timestamp_ms")] ulong TimestampMs,
    [property: JsonPropertyName("level")] string Level,
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("peer")] string? Peer);

public sealed record AnalyticsSummary(
    [property: JsonPropertyName("n")] int N,
    [property: JsonPropertyName("m")] int M,
    [property: JsonPropertyName("j")] int J,
    [property: JsonPropertyName("i2p_routes")] string I2pRoutes,
    [property: JsonPropertyName("f1_routes")] string F1Routes,
    [property: JsonPropertyName("f3_routes")] string F3Routes,
    [property: JsonPropertyName("f4_routes")] string F4Routes,
    [property: JsonPropertyName("f1_entropy_bits")] double F1EntropyBits,
    [property: JsonPropertyName("f3_entropy_bits")] double F3EntropyBits,
    [property: JsonPropertyName("f4_entropy_bits")] double F4EntropyBits,
    [property: JsonPropertyName("f1_compromise_pct")] double F1CompromisePct,
    [property: JsonPropertyName("f3_compromise_pct")] double F3CompromisePct,
    [property: JsonPropertyName("f4_compromise_pct")] double F4CompromisePct,
    [property: JsonPropertyName("f1_n50")] int? F1N50,
    [property: JsonPropertyName("f3_n50")] int? F3N50,
    [property: JsonPropertyName("f4_n50")] int? F4N50,
    [property: JsonPropertyName("f4_monte_carlo_pct")] double? F4MonteCarloPct,
    [property: JsonPropertyName("f4_monte_carlo_abs_error")] double? F4MonteCarloAbsError,
    [property: JsonPropertyName("f4_monte_carlo_ms")] double? F4MonteCarloMs);

public sealed class CcoFfiException(string errorCode) : Exception($"CCO FFI error: {errorCode}")
{
    public string ErrorCode { get; } = errorCode;
}

public static class CcoClient
{
    public static readonly string[] AllowedMccModes = ["first", "window", "adaptive", "wait-all"];

    public static string GetVersion() => NativeCcoFfi.TakeRustString(NativeCcoFfi.cco_version());

    public static TrustStatus VerifyTrustBundle(
        string registryJson,
        string rootJson,
        IReadOnlyList<string> requiredNodes)
    {
        var reqJson = JsonSerializer.Serialize(requiredNodes);
        var raw = NativeCcoFfi.TakeRustString(
            NativeCcoFfi.cco_verify_trust_bundle(registryJson, rootJson, reqJson));
        return Unwrap<TrustStatus>(raw);
    }

    public static AnalyticsSummary RunAnalyticsSummary(int n, int m, int j)
    {
        if (n < 3 || m < 0 || j <= 0)
        {
            throw new CcoFfiException("invalid_analytics_parameters");
        }

        var raw = NativeCcoFfi.TakeRustString(
            NativeCcoFfi.cco_analytics_summary((uint)n, (uint)m, (uint)j));
        return Unwrap<AnalyticsSummary>(raw);
    }

    public static string GenerateDemoProfileJson(string localNode = "A", string peerNode = "B")
    {
        var raw = NativeCcoFfi.TakeRustString(
            NativeCcoFfi.cco_generate_demo_bundle(localNode, peerNode));
        var node = JsonNode.Parse(raw)?.AsObject()
                   ?? throw new CcoFfiException("json_parse_error");
        if (node["ok"]?.GetValue<bool>() != true || node["data"] is null)
        {
            throw new CcoFfiException(node["error"]?.GetValue<string>() ?? "demo_generation_failed");
        }

        return node["data"]!.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }

    public static string PrepareTunnelStartConfig(
        string profileJson,
        string replayDbPath,
        string mccMode,
        int x1Fanout,
        int x2Fanout,
        bool initiateHandshake = true)
    {
        if (!AllowedMccModes.Contains(mccMode, StringComparer.Ordinal))
        {
            throw new CcoFfiException("invalid_mcc_mode");
        }

        var obj = JsonNode.Parse(profileJson)?.AsObject()
                  ?? throw new CcoFfiException("invalid_profile_json");
        obj["replay_db_path"] = replayDbPath;
        obj["mcc_mode"] = mccMode;
        obj["x1_fanout"] = Math.Clamp(x1Fanout, 1, 8);
        obj["x2_fanout"] = Math.Clamp(x2Fanout, 1, 8);
        obj["ike_fanout"] = 1;
        obj["has_pi_header"] = false;
        obj["initiate_handshake"] = initiateHandshake;
        return obj.ToJsonString();
    }

    internal static T Unwrap<T>(string rawJson)
    {
        var env = JsonSerializer.Deserialize<FfiEnvelope<T>>(rawJson)
                  ?? throw new CcoFfiException("json_parse_error");
        if (!env.Ok || env.Data is null)
        {
            throw new CcoFfiException(env.Error ?? "unknown_ffi_error");
        }

        return env.Data;
    }
}

/// <summary>
/// Safe managed wrapper around an active Rust <c>CcoTunnelHandle</c>.
/// </summary>
public sealed class CcoTunnelSession : IDisposable
{
    private IntPtr _handle;
    private readonly object _gate = new();

    private CcoTunnelSession(IntPtr handle)
    {
        _handle = handle;
    }

    public static CcoTunnelSession StartChannel(string configJson)
    {
        var handle = NativeCcoFfi.cco_tunnel_start_channel(configJson, out var errPtr);
        if (handle == IntPtr.Zero)
        {
            var err = NativeCcoFfi.TakeRustString(errPtr);
            throw new CcoFfiException(string.IsNullOrWhiteSpace(err) ? "tunnel_start_failed" : err);
        }

        return new CcoTunnelSession(handle);
    }

    public bool InitiateHandshake()
    {
        lock (_gate)
        {
            return _handle != IntPtr.Zero && NativeCcoFfi.cco_tunnel_initiate(_handle) == 0;
        }
    }

    public int PushOutboundIp(byte[] packet, int length)
    {
        lock (_gate)
        {
            if (_handle == IntPtr.Zero) return -1;
            return NativeCcoFfi.cco_tunnel_push_outbound_ip(_handle, packet, (nuint)length);
        }
    }

    public int PopInboundIp(byte[] buffer)
    {
        lock (_gate)
        {
            if (_handle == IntPtr.Zero) return -1;
            return (int)NativeCcoFfi.cco_tunnel_pop_inbound_ip(_handle, buffer, (nuint)buffer.Length);
        }
    }

    public TunnelStats GetStats()
    {
        lock (_gate)
        {
            if (_handle == IntPtr.Zero)
            {
                throw new CcoFfiException("tunnel_stopped");
            }

            var raw = NativeCcoFfi.TakeRustString(NativeCcoFfi.cco_tunnel_stats(_handle));
            return CcoClient.Unwrap<TunnelStats>(raw);
        }
    }

    public List<SanitizedEvent> DrainEvents()
    {
        lock (_gate)
        {
            if (_handle == IntPtr.Zero) return [];
            var raw = NativeCcoFfi.TakeRustString(NativeCcoFfi.cco_tunnel_drain_events(_handle));
            return CcoClient.Unwrap<List<SanitizedEvent>>(raw);
        }
    }

    public void Dispose()
    {
        IntPtr toStop;
        lock (_gate)
        {
            toStop = _handle;
            _handle = IntPtr.Zero;
        }

        if (toStop != IntPtr.Zero)
        {
            NativeCcoFfi.cco_tunnel_stop(toStop);
        }
    }
}
