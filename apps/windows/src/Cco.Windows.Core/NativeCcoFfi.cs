using System.Runtime.InteropServices;

namespace Cco.Windows.Core;

/// <summary>
/// Direct P/Invoke bindings matching <c>crates/cco-ffi/include/cco_ffi.h</c> (<c>cco_ffi.dll</c>).
/// </summary>
public static class NativeCcoFfi
{
    private const string LibName = "cco_ffi";

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr cco_version();

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void cco_string_free(IntPtr ptr);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr cco_verify_trust_bundle(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string registryJson,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string rootJson,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string requiredNodesJson);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr cco_analytics_summary(uint n, uint m, uint j);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr cco_generate_demo_bundle(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string localNode,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string peerNode);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr cco_tunnel_start_channel(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string configJson,
        out IntPtr errOut);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int cco_tunnel_initiate(IntPtr handle);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int cco_tunnel_push_outbound_ip(
        IntPtr handle,
        byte[] data,
        nuint len);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern nint cco_tunnel_pop_inbound_ip(
        IntPtr handle,
        byte[] outBuf,
        nuint capacity);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr cco_tunnel_stats(IntPtr handle);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr cco_tunnel_drain_events(IntPtr handle);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void cco_tunnel_stop(IntPtr handle);

    public static string TakeRustString(IntPtr ptr)
    {
        if (ptr == IntPtr.Zero)
        {
            return string.Empty;
        }

        try
        {
            return Marshal.PtrToStringUTF8(ptr) ?? string.Empty;
        }
        finally
        {
            cco_string_free(ptr);
        }
    }
}
