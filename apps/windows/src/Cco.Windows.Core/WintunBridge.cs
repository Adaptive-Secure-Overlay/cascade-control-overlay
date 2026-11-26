using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Cco.Windows.Core;

/// <summary>
/// Official signed Wintun 0.14.1 adapter bridge pumping L3 IP packets between Windows
/// and <see cref="CcoTunnelSession"/> (zero unsigned kernel drivers, full cleanup on exit).
/// </summary>
public sealed class WintunBridge : IDisposable
{
    private const uint RingCapacityBytes = 0x400000; // 4 MiB ring buffer
    private const uint WaitObject0 = 0x00000000;

    private readonly CcoTunnelSession _tunnel;
    private readonly string _adapterName;
    private readonly string _tunnelIp;
    private readonly string _subnetMask;
    private readonly CancellationTokenSource _cts = new();

    private IntPtr _adapter;
    private IntPtr _session;
    private Task? _rxTask;
    private Task? _txTask;
    private bool _disposed;

    public WintunBridge(
        CcoTunnelSession tunnel,
        string adapterName = "CCO-Overlay0",
        string tunnelIp = "198.51.100.10",
        string subnetMask = "255.255.255.0")
    {
        _tunnel = tunnel;
        _adapterName = adapterName;
        _tunnelIp = tunnelIp;
        _subnetMask = subnetMask;
    }

    public static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    public void Start()
    {
        if (!IsAdministrator())
        {
            throw new CcoFfiException("administrator_privileges_required_for_wintun");
        }

        var guid = new Guid("8F7441A8-7A24-4B1C-8A06-2306C0000001");
        _adapter = WintunCreateAdapter(_adapterName, "CascadeControlOverlay", ref guid);
        if (_adapter == IntPtr.Zero)
        {
            throw new CcoFfiException($"wintun_create_adapter_failed_{Marshal.GetLastWin32Error()}");
        }

        ConfigureInterfaceAddress(_adapterName, _tunnelIp, _subnetMask);

        _session = WintunStartSession(_adapter, RingCapacityBytes);
        if (_session == IntPtr.Zero)
        {
            WintunCloseAdapter(_adapter);
            _adapter = IntPtr.Zero;
            throw new CcoFfiException($"wintun_start_session_failed_{Marshal.GetLastWin32Error()}");
        }

        AppDomain.CurrentDomain.ProcessExit += OnProcessExit;
        _rxTask = Task.Run(() => PumpWintunToRust(_cts.Token), _cts.Token);
        _txTask = Task.Run(() => PumpRustToWintun(_cts.Token), _cts.Token);
    }

    private void PumpWintunToRust(CancellationToken ct)
    {
        var readEvent = WintunGetReadWaitEvent(_session);
        var scratch = new byte[65536];

        while (!ct.IsCancellationRequested)
        {
            var pktPtr = WintunReceivePacket(_session, out var pktSize);
            if (pktPtr != IntPtr.Zero)
            {
                try
                {
                    if (pktSize > 0 && pktSize <= scratch.Length)
                    {
                        Marshal.Copy(pktPtr, scratch, 0, (int)pktSize);
                        _tunnel.PushOutboundIp(scratch, (int)pktSize);
                    }
                }
                finally
                {
                    WintunReleaseReceivePacket(_session, pktPtr);
                }
            }
            else
            {
                var err = Marshal.GetLastWin32Error();
                if (err == 259) // ERROR_NO_MORE_ITEMS
                {
                    WaitForSingleObject(readEvent, 50);
                }
                else
                {
                    Thread.Sleep(10);
                }
            }
        }
    }

    private void PumpRustToWintun(CancellationToken ct)
    {
        var buf = new byte[65536];
        while (!ct.IsCancellationRequested)
        {
            var n = _tunnel.PopInboundIp(buf);
            if (n > 0)
            {
                var outPtr = WintunAllocateSendPacket(_session, (uint)n);
                if (outPtr != IntPtr.Zero)
                {
                    Marshal.Copy(buf, 0, outPtr, n);
                    WintunSendPacket(_session, outPtr);
                }
            }
            else
            {
                Thread.Sleep(2);
            }
        }
    }

    private static void ConfigureInterfaceAddress(string name, string ip, string mask)
    {
        RunNetsh($"interface ipv4 set address name=\"{name}\" static {ip} {mask}");
        RunNetsh($"interface ipv4 set subinterface \"{name}\" mtu=1420 store=active");
    }

    private static void RunNetsh(string args)
    {
        using var proc = Process.Start(new ProcessStartInfo
        {
            FileName = "netsh.exe",
            Arguments = args,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        });
        proc?.WaitForExit(5000);
    }

    private void OnProcessExit(object? sender, EventArgs e) => Dispose();

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        AppDomain.CurrentDomain.ProcessExit -= OnProcessExit;
        _cts.Cancel();

        try { Task.WaitAll([_rxTask ?? Task.CompletedTask, _txTask ?? Task.CompletedTask], 1000); }
        catch { /* best-effort teardown */ }

        if (_session != IntPtr.Zero)
        {
            WintunEndSession(_session);
            _session = IntPtr.Zero;
        }

        if (_adapter != IntPtr.Zero)
        {
            WintunCloseAdapter(_adapter);
            _adapter = IntPtr.Zero;
        }

        _cts.Dispose();
    }

    [DllImport("wintun.dll", EntryPoint = "WintunCreateAdapter", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr WintunCreateAdapter(string name, string tunnelType, ref Guid requestedGuid);

    [DllImport("wintun.dll", EntryPoint = "WintunCloseAdapter", SetLastError = true)]
    private static extern void WintunCloseAdapter(IntPtr adapter);

    [DllImport("wintun.dll", EntryPoint = "WintunStartSession", SetLastError = true)]
    private static extern IntPtr WintunStartSession(IntPtr adapter, uint capacity);

    [DllImport("wintun.dll", EntryPoint = "WintunEndSession", SetLastError = true)]
    private static extern void WintunEndSession(IntPtr session);

    [DllImport("wintun.dll", EntryPoint = "WintunGetReadWaitEvent", SetLastError = true)]
    private static extern IntPtr WintunGetReadWaitEvent(IntPtr session);

    [DllImport("wintun.dll", EntryPoint = "WintunReceivePacket", SetLastError = true)]
    private static extern IntPtr WintunReceivePacket(IntPtr session, out uint packetSize);

    [DllImport("wintun.dll", EntryPoint = "WintunReleaseReceivePacket", SetLastError = true)]
    private static extern void WintunReleaseReceivePacket(IntPtr session, IntPtr packet);

    [DllImport("wintun.dll", EntryPoint = "WintunAllocateSendPacket", SetLastError = true)]
    private static extern IntPtr WintunAllocateSendPacket(IntPtr session, uint packetSize);

    [DllImport("wintun.dll", EntryPoint = "WintunSendPacket", SetLastError = true)]
    private static extern void WintunSendPacket(IntPtr session, IntPtr packet);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
}
