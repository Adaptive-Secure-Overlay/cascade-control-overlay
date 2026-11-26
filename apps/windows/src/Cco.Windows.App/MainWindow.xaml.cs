using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using Cco.Windows.Core;
using Microsoft.Win32;

namespace Cco.Windows.App;

public partial class MainWindow : Window
{
    private readonly DispatcherTimer _pollTimer;
    private string? _profileJson;
    private TrustStatus? _trustStatus;
    private CcoTunnelSession? _session;
    private WintunBridge? _wintun;

    public MainWindow()
    {
        InitializeComponent();
        _pollTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
        _pollTimer.Tick += PollTimer_Tick;

        try
        {
            var version = CcoClient.GetVersion();
            HeaderSubtitle.Text = $"Rust cco-ffi v{version} + Official Signed Wintun 0.14.1 · Open-Source MIT/Apache-2.0";
        }
        catch (Exception ex)
        {
            TunnelErrorText.Text = $"Failed to load cco_ffi.dll: {ex.Message}";
        }

        Closing += (_, _) => StopTunnel();
    }

    private void GenerateDemo_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var demo = CcoClient.GenerateDemoProfileJson("A", "B");
            LoadAndVerifyProfile(demo);
            TunnelErrorText.Text = string.Empty;
        }
        catch (Exception ex)
        {
            TunnelErrorText.Text = ex.Message;
        }
    }

    private void ImportProfile_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Filter = "CCO Profile JSON (*.json)|*.json|All Files (*.*)|*.*",
            Title = "Select Signed CCO Profile JSON",
        };
        if (dlg.ShowDialog() == true)
        {
            try
            {
                LoadAndVerifyProfile(File.ReadAllText(dlg.FileName));
                TunnelErrorText.Text = string.Empty;
            }
            catch (Exception ex)
            {
                TunnelErrorText.Text = ex.Message;
            }
        }
    }

    private void LoadAndVerifyProfile(string rawJson)
    {
        var obj = JsonNode.Parse(rawJson)?.AsObject()
                  ?? throw new CcoFfiException("invalid_profile_json");
        var regJson = obj["trust_registry_json"]?.GetValue<string>()
                      ?? throw new CcoFfiException("missing_trust_registry_json");
        var rootJson = obj["trust_root_json"]?.GetValue<string>()
                       ?? throw new CcoFfiException("missing_trust_root_json");
        var peers = obj["peers"]?.AsArray()
                    ?? throw new CcoFfiException("missing_peers");
        var required = peers
            .Select(p => p?["name"]?.GetValue<string>())
            .Where(n => !string.IsNullOrWhiteSpace(n))
            .Cast<string>()
            .ToList();

        _trustStatus = CcoClient.VerifyTrustBundle(regJson, rootJson, required);
        _profileJson = rawJson;
        TrustStatusText.Text =
            $"VERIFIED Trust Registry v{_trustStatus.Version} | signer={_trustStatus.SignerKeyId} | " +
            $"nodes=[{string.Join(", ", _trustStatus.Nodes)}] | sha256={_trustStatus.Sha256[..16]}...";
        TrustStatusText.Foreground = new SolidColorBrush(Color.FromRgb(0x34, 0xD3, 0x99));
    }

    private void ConnectButton_Click(object sender, RoutedEventArgs e)
    {
        if (_session is not null)
        {
            StopTunnel();
            return;
        }

        if (_profileJson is null || _trustStatus?.Authenticated != true)
        {
            TunnelErrorText.Text = "Load or generate a verified Trust Registry v2 profile first.";
            return;
        }

        try
        {
            var mode = (MccModeCombo.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "adaptive";
            var x1 = int.TryParse(X1FanoutBox.Text, out var parsedX1) ? parsedX1 : 2;
            var x2 = int.TryParse(X2FanoutBox.Text, out var parsedX2) ? parsedX2 : 2;
            var appData = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "CascadeControlOverlay");
            Directory.CreateDirectory(appData);
            var replayDb = Path.Combine(appData, "replay.sqlite");

            var cfgJson = CcoClient.PrepareTunnelStartConfig(_profileJson, replayDb, mode, x1, x2);
            _session = CcoTunnelSession.StartChannel(cfgJson);

            _wintun = new WintunBridge(_session, "CCO-Overlay0", TunIpBox.Text.Trim(), "255.255.255.0");
            _wintun.Start();

            ConnectButton.Content = "Disconnect";
            RekeyButton.IsEnabled = true;
            TunnelErrorText.Text = string.Empty;
            TunnelStateText.Text = "HANDSHAKING VIA MCC OVERLAY (A -> X1 -> X2 -> B)";
            TunnelStateText.Foreground = new SolidColorBrush(Color.FromRgb(0xFB, 0xBF, 0x24));
            _pollTimer.Start();
        }
        catch (Exception ex)
        {
            StopTunnel();
            TunnelErrorText.Text = ex.Message;
        }
    }

    private void RekeyButton_Click(object sender, RoutedEventArgs e)
    {
        _session?.InitiateHandshake();
    }

    private void PollTimer_Tick(object? sender, EventArgs e)
    {
        if (_session is null) return;
        try
        {
            var stats = _session.GetStats();
            TunnelStateText.Text = stats.State.ToUpperInvariant();
            TunnelStateText.Foreground = stats.State == "connected_direct_data"
                ? new SolidColorBrush(Color.FromRgb(0x34, 0xD3, 0x99))
                : new SolidColorBrush(Color.FromRgb(0xFB, 0xBF, 0x24));

            InvariantBadge.Text = stats.ControlPlaneInvariantHolds
                ? "DIRECT WG HANDSHAKE TX = 0 (VERIFIED)"
                : $"INVARIANT VIOLATION: {stats.DirectHandshakeTx}";
            InvariantBadge.Foreground = stats.ControlPlaneInvariantHolds
                ? new SolidColorBrush(Color.FromRgb(0x34, 0xD3, 0x99))
                : new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71));

            TelemetrySummaryText.Text =
                $"State:                     {stats.State}\n" +
                $"Direct Handshake TX:       {stats.DirectHandshakeTx} (INVARIANT: MUST BE 0)\n" +
                $"Direct Handshake Dropped:  {stats.DirectHandshakeRxDropped}\n" +
                $"Overlay Handshake TX/RX:   {stats.OverlayHandshakeTx} / {stats.OverlayHandshakeRx}\n" +
                $"Direct WG Type 4 TX/RX:    {stats.DirectDataTx} / {stats.DirectDataRx}\n" +
                $"Direct Data Bytes TX/RX:   {stats.DirectBytesTx} B / {stats.DirectBytesRx} B\n" +
                $"Initial Handshake Latency: {(stats.HandshakeMs.HasValue ? $"{stats.HandshakeMs} ms" : "pending")}\n" +
                $"Selected X1 (X2 hidden):   {stats.SelectedX1 ?? "pending"}\n" +
                $"MCC Mode / Hops:           {stats.MccMode} / {stats.SelectedRouteHops} hops\n" +
                $"Trust Registry v2:         v{stats.TrustRegistryVersion} ({stats.TrustRegistrySha256})";

            foreach (var ev in _session.DrainEvents())
            {
                EventsList.Items.Insert(0, $"[{ev.Level.ToUpperInvariant()}] {ev.Code} peer={ev.Peer ?? "-"}");
                while (EventsList.Items.Count > 120)
                {
                    EventsList.Items.RemoveAt(EventsList.Items.Count - 1);
                }
            }
        }
        catch (Exception ex)
        {
            TunnelErrorText.Text = ex.Message;
        }
    }

    private void ComputeAnalytics_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var n = int.Parse(AnalyticsN.Text);
            var m = int.Parse(AnalyticsM.Text);
            var j = int.Parse(AnalyticsJ.Text);
            var s = CcoClient.RunAnalyticsSummary(n, m, j);

            AnalyticsOutputText.Text =
                $"Parameters: n={s.N}, m={s.M}, j={s.J}\n" +
                $"I2P routes:     {s.I2pRoutes}\n" +
                $"F1 (Tor):       {s.F1Routes} routes | H={s.F1EntropyBits:F4} bits | P={s.F1CompromisePct:F2}% | n50={s.F1N50?.ToString() ?? "-"}\n" +
                $"F3 (No-Rep):    {s.F3Routes} routes | H={s.F3EntropyBits:F4} bits | P={s.F3CompromisePct:F2}% | n50={s.F3N50?.ToString() ?? "-"}\n" +
                $"F4 (With-Rep):  {s.F4Routes} routes | H={s.F4EntropyBits:F4} bits | P={s.F4CompromisePct:F2}% | n50={s.F4N50?.ToString() ?? "-"}\n" +
                $"Rayon MC 100k:  {s.F4MonteCarloPct:F2}% (abs_err={s.F4MonteCarloAbsError:F5}, elapsed={s.F4MonteCarloMs:F2} ms)";
        }
        catch (Exception ex)
        {
            AnalyticsOutputText.Text = $"Error: {ex.Message}";
        }
    }

    private void StopTunnel()
    {
        _pollTimer.Stop();
        _wintun?.Dispose();
        _wintun = null;
        _session?.Dispose();
        _session = null;
        ConnectButton.Content = "Connect Split VPN (Wintun)";
        RekeyButton.IsEnabled = false;
        TunnelStateText.Text = "DISCONNECTED";
        TunnelStateText.Foreground = new SolidColorBrush(Color.FromRgb(0x94, 0xA3, 0xB8));
    }
}
