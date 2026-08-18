using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// The hand-rolled COM-callable wrapper for <c>IVpnPlugIn</c> — the authoring twin of
/// <see cref="VpnChannelAbi"/>.
/// </summary>
/// <remarks>
/// <para>
/// The CsWinRT-authored CCW materializes projected wrappers for every event's parameters — the
/// channel, the two lists, the encap buffer — which at delivery granularity is packet-path
/// allocation (measured: 38 gen0 collections per ~200k visits, and ~26/30 s during a 130 Mbit/s
/// download). This vtable's stubs receive the raw interface pointers and hand them, borrowed, to
/// <see cref="SSHVpnPlugin"/>'s raw cores: zero WinRT objects per event, and the per-batch
/// QI dance dissolves because <c>Encapsulate</c>'s and <c>Decapsulate</c>'s parameters already
/// ARE the <c>IVpnPacketBufferList</c> pointers the old path re-derived.
/// </para>
/// <para>
/// One static object for the host's lifetime: refcounting is a no-op, the vtable and the
/// one-pointer object live in never-freed native memory, and the QI answers IUnknown,
/// IInspectable, IAgileObject (free-threaded — the stubs have no affinity) and IVpnPlugIn.
/// Slot order and signatures are transcribed from windows.networking.vpn.h:15557: 6 Connect,
/// 7 Disconnect, 8 GetKeepAlivePayload, 9 Encapsulate, 10 Decapsulate.
/// </para>
/// <para>
/// Stubs must never let an exception cross the ABI — each catches everything and returns the
/// exception's HRESULT, mirroring what <c>VpnBackgroundTask.Run</c> always guaranteed.
/// </para>
/// </remarks>
internal static unsafe class VpnPlugInCcw
{
    private static readonly Guid IID_IUnknown = new("00000000-0000-0000-c000-000000000046");
    private static readonly Guid IID_IInspectable = new("af86e2e0-b12d-4c6a-9c5a-d7aa65101e90");
    private static readonly Guid IID_IAgileObject = new("94ea2b94-e9cc-49e0-c0ff-ee64ca8f5b90");

    private static SSHVpnPlugin? _plugin;
    private static IntPtr _ccw;
    private static int _unknownQiLogs;

    /// <summary>
    /// Gets the CCW for <paramref name="plugin"/>, building it on first use.
    /// </summary>
    /// <remarks>
    /// The instance is process-wide, like the plug-in it fronts (one profile per process). The
    /// native allocations are deliberately never freed: the platform may hold the pointer for the
    /// host's whole life, and the host exits rather than unloads.
    /// </remarks>
    public static IntPtr GetOrCreate(SSHVpnPlugin plugin)
    {
        ArgumentNullException.ThrowIfNull(plugin);

        _plugin = plugin;

        if (_ccw != default)
        {
            return _ccw;
        }

        var vtable = (IntPtr*)NativeMemory.AllocZeroed(11, (nuint)sizeof(IntPtr));
        vtable[0] = (IntPtr)(delegate* unmanaged[Stdcall]<void*, Guid*, void**, int>)&QueryInterface;
        vtable[1] = (IntPtr)(delegate* unmanaged[Stdcall]<void*, uint>)&AddRef;
        vtable[2] = (IntPtr)(delegate* unmanaged[Stdcall]<void*, uint>)&Release;
        vtable[3] = (IntPtr)(delegate* unmanaged[Stdcall]<void*, uint*, Guid**, int>)&GetIids;
        vtable[4] = (IntPtr)(delegate* unmanaged[Stdcall]<void*, IntPtr*, int>)&GetRuntimeClassName;
        vtable[5] = (IntPtr)(delegate* unmanaged[Stdcall]<void*, int*, int>)&GetTrustLevel;
        vtable[6] = (IntPtr)(delegate* unmanaged[Stdcall]<void*, void*, int>)&Connect;
        vtable[7] = (IntPtr)(delegate* unmanaged[Stdcall]<void*, void*, int>)&Disconnect;
        vtable[8] = (IntPtr)(delegate* unmanaged[Stdcall]<void*, void*, void**, int>)&GetKeepAlivePayload;
        vtable[9] = (IntPtr)(delegate* unmanaged[Stdcall]<void*, void*, void*, void*, int>)&Encapsulate;
        vtable[10] = (IntPtr)(delegate* unmanaged[Stdcall]<void*, void*, void*, void*, void*, int>)&Decapsulate;

        var instance = (IntPtr*)NativeMemory.AllocZeroed(1, (nuint)sizeof(IntPtr));
        instance[0] = (IntPtr)vtable;

        _ccw = (IntPtr)instance;
        PluginLog.Info("Hand-rolled IVpnPlugIn CCW created");
        return _ccw;
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static int QueryInterface(void* thisPtr, Guid* riid, void** ppv)
    {
        if (ppv == null)
        {
            return unchecked((int)0x80004003); // E_POINTER
        }

        var iid = *riid;
        if (iid == IID_IUnknown || iid == IID_IInspectable || iid == IID_IAgileObject
            || iid == VpnChannelAbi.IID_IVpnPlugIn)
        {
            *ppv = thisPtr;
            return 0;
        }

        *ppv = null;

        if (Interlocked.Increment(ref _unknownQiLogs) <= 10)
        {
            PluginLog.Info($"CCW: QueryInterface for {iid} answered E_NOINTERFACE");
        }

        return unchecked((int)0x80004002); // E_NOINTERFACE
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static uint AddRef(void* thisPtr)
    {
        // Static lifetime; the count is decorative.
        return 2;
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static uint Release(void* thisPtr)
    {
        return 1;
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static int GetIids(void* thisPtr, uint* iidCount, Guid** iids)
    {
        if (iidCount == null || iids == null)
        {
            return unchecked((int)0x80004003); // E_POINTER
        }

        var array = (Guid*)Marshal.AllocCoTaskMem(sizeof(Guid));
        *array = VpnChannelAbi.IID_IVpnPlugIn;
        *iids = array;
        *iidCount = 1;
        return 0;
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static int GetRuntimeClassName(void* thisPtr, IntPtr* className)
    {
        const string Name = "PoiTech.WSSHVpnPlugin.VpnPlugin.SSHVpnPlugin";

        fixed (char* chars = Name)
        {
            return WindowsCreateString((ushort*)chars, (uint)Name.Length, className);
        }
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static int GetTrustLevel(void* thisPtr, int* trustLevel)
    {
        if (trustLevel != null)
        {
            *trustLevel = 0; // BaseTrust
        }

        return 0;
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static int Connect(void* thisPtr, void* channel)
    {
        try
        {
            _plugin?.ConnectRaw((IntPtr)channel);
            return 0;
        }
        catch (Exception ex)
        {
            PluginLog.Error("CCW Connect failed", ex);
            return ex.HResult != 0 ? ex.HResult : unchecked((int)0x80004005);
        }
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static int Disconnect(void* thisPtr, void* channel)
    {
        try
        {
            _plugin?.DisconnectRaw((IntPtr)channel);
            return 0;
        }
        catch (Exception ex)
        {
            PluginLog.Error("CCW Disconnect failed", ex);
            return ex.HResult != 0 ? ex.HResult : unchecked((int)0x80004005);
        }
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static int GetKeepAlivePayload(void* thisPtr, void* channel, void** keepAlivePacket)
    {
        try
        {
            if (keepAlivePacket != null)
            {
                *keepAlivePacket = null;
            }

            _plugin?.NoteKeepAliveAsked();
            return 0;
        }
        catch (Exception ex)
        {
            PluginLog.Error("CCW GetKeepAlivePayload failed", ex);
            return ex.HResult != 0 ? ex.HResult : unchecked((int)0x80004005);
        }
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static int Encapsulate(void* thisPtr, void* channel, void* packets, void* encapsulatedPackets)
    {
        try
        {
            _plugin?.EncapsulateRaw((IntPtr)channel, (IntPtr)packets);
            return 0;
        }
        catch (Exception ex)
        {
            PluginLog.Error("CCW Encapsulate failed", ex);
            return ex.HResult != 0 ? ex.HResult : unchecked((int)0x80004005);
        }
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static int Decapsulate(void* thisPtr, void* channel, void* encapBuffer, void* decapsulatedPackets, void* controlPacketsToSend)
    {
        try
        {
            _plugin?.DecapsulateRaw((IntPtr)encapBuffer, (IntPtr)decapsulatedPackets);
            return 0;
        }
        catch (Exception ex)
        {
            PluginLog.Error("CCW Decapsulate failed", ex);
            return ex.HResult != 0 ? ex.HResult : unchecked((int)0x80004005);
        }
    }

    [DllImport("combase.dll")]
    private static extern int WindowsCreateString(ushort* sourceString, uint length, IntPtr* hstring);
}
