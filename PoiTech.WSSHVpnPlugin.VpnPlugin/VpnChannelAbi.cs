using System;
using System.Runtime.InteropServices;
using Windows.Networking.Vpn;
using WinRT;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// Raw vtable access to the WinRT interfaces on the packet path.
/// </summary>
/// <remarks>
/// <para>
/// The rule this exists to enforce: <b>never create a WinRT object on the packet path</b>. The
/// projected API costs an RCW per <c>GetVpnReceivePacketBuffer</c>, per <c>RemoveAtBegin</c>, and
/// per <c>.Buffer</c> property get — allocation and finalization pressure on both hot threads for
/// objects that live microseconds. Here the per-packet interop is a plain indirect call through a
/// cached interface pointer, and the inbound queue carries the pointers themselves.
/// </para>
/// <para>
/// Every IID and slot index below was transcribed from the MIDL-generated headers in
/// <c>C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\winrt\</c> — not from memory or
/// intuition, because this family has traps: <c>GetVpnReceivePacketBuffer</c> is on
/// <c>IVpnChannel2</c>, not <c>IVpnChannel</c> (whose same-numbered slot is
/// <c>LogDiagnosticMessage</c>); <c>put_Status</c> precedes <c>get_Status</c> on
/// <c>IVpnPacketBuffer</c>; and <c>RemoveAtEnd</c> precedes <c>RemoveAtBegin</c> on
/// <c>IVpnPacketBufferList</c>. A wrong slot with the same signature cannot be caught at runtime,
/// so the header citation next to each constant is the review surface.
/// </para>
/// <para>
/// Ownership contract, uniform across these helpers: every interface pointer returned through an
/// out-parameter — including from <see cref="QueryInterface"/> — carries a reference the caller
/// must <see cref="Release"/> exactly once. <c>ListAppend</c> copies: the list takes its own
/// reference, so the caller's must still be released. Success is <c>hr &gt;= 0</c>.
/// </para>
/// </remarks>
internal static unsafe class VpnChannelAbi
{
    // windows.networking.vpn.h:3496
    internal static readonly Guid IID_IVpnChannel2 = new("2255d165-993b-4629-ad60-f1c3f3537f50");

    // windows.networking.vpn.h:5097
    internal static readonly Guid IID_IVpnPacketBuffer = new("c2f891fc-4d5c-4a63-b70d-4e307eacce55");

    // windows.networking.vpn.h:5260
    internal static readonly Guid IID_IVpnPacketBufferList = new("c2f891fc-4d5c-4a63-b70d-4e307eacce77");

    // windows.storage.streams.h:1324 — ends 0fe0; IBufferByteAccess ends 0fef. One nibble apart.
    internal static readonly Guid IID_IBuffer = new("905a0fe0-bc53-11df-8c49-001e4fc686da");

    // robuffer.h:27
    internal static readonly Guid IID_IBufferByteAccess = new("905a0fef-bc53-11df-8c49-001e4fc686da");

    /// <summary>IUnknown slot 0.</summary>
    internal static int QueryInterface(IntPtr ptr, in Guid iid, out IntPtr result)
    {
        var value = default(IntPtr);
        int hr;

        fixed (Guid* riid = &iid)
        {
            hr = ((delegate* unmanaged[Stdcall]<void*, Guid*, void**, int>)(*(void***)ptr)[0])(
                (void*)ptr, riid, (void**)&value);
        }

        result = value;
        return hr;
    }

    /// <summary>IUnknown slot 2. Tolerates zero so cleanup paths need no guards.</summary>
    internal static void Release(IntPtr ptr)
    {
        if (ptr == default)
        {
            return;
        }

        _ = ((delegate* unmanaged[Stdcall]<void*, uint>)(*(void***)ptr)[2])((void*)ptr);
    }

    /// <summary>IVpnChannel2 slot 11 — windows.networking.vpn.h:12095. Slot 10 is GetVpnSendPacketBuffer.</summary>
    internal static int GetReceiveBuffer(IntPtr channel2, out IntPtr packetBuffer)
    {
        var value = default(IntPtr);
        var hr = ((delegate* unmanaged[Stdcall]<void*, void**, int>)(*(void***)channel2)[11])(
            (void*)channel2, (void**)&value);

        packetBuffer = value;
        return hr;
    }

    /// <summary>IVpnPacketBuffer slot 6, get_Buffer — windows.networking.vpn.h:15001.</summary>
    internal static int GetBuffer(IntPtr packetBuffer, out IntPtr buffer)
    {
        var value = default(IntPtr);
        var hr = ((delegate* unmanaged[Stdcall]<void*, void**, int>)(*(void***)packetBuffer)[6])(
            (void*)packetBuffer, (void**)&value);

        buffer = value;
        return hr;
    }

    /// <summary>IBuffer slot 6, get_Capacity — windows.storage.streams.h:4140.</summary>
    internal static int GetCapacity(IntPtr buffer, out uint capacity)
    {
        uint value = 0;
        var hr = ((delegate* unmanaged[Stdcall]<void*, uint*, int>)(*(void***)buffer)[6])(
            (void*)buffer, &value);

        capacity = value;
        return hr;
    }

    /// <summary>IBuffer slot 7, get_Length — windows.storage.streams.h:4142.</summary>
    internal static int GetLength(IntPtr buffer, out uint length)
    {
        uint value = 0;
        var hr = ((delegate* unmanaged[Stdcall]<void*, uint*, int>)(*(void***)buffer)[7])(
            (void*)buffer, &value);

        length = value;
        return hr;
    }

    /// <summary>IBuffer slot 8, put_Length — windows.storage.streams.h:4144.</summary>
    internal static int SetLength(IntPtr buffer, uint length)
    {
        return ((delegate* unmanaged[Stdcall]<void*, uint, int>)(*(void***)buffer)[8])(
            (void*)buffer, length);
    }

    /// <summary>
    /// IBufferByteAccess slot 3, Buffer — robuffer.h:30. Derives from IUnknown, not IInspectable,
    /// so there are no IInspectable slots and the first method is slot 3, not 6.
    /// </summary>
    internal static int GetBytes(IntPtr byteAccess, out byte* data)
    {
        byte* value = null;
        var hr = ((delegate* unmanaged[Stdcall]<void*, byte**, int>)(*(void***)byteAccess)[3])(
            (void*)byteAccess, &value);

        data = value;
        return hr;
    }

    /// <summary>IVpnPacketBufferList slot 6, Append — windows.networking.vpn.h:15306. The list takes its own reference.</summary>
    internal static int ListAppend(IntPtr list, IntPtr packetBuffer)
    {
        return ((delegate* unmanaged[Stdcall]<void*, void*, int>)(*(void***)list)[6])(
            (void*)list, (void*)packetBuffer);
    }

    /// <summary>IVpnPacketBufferList slot 9, RemoveAtBegin — windows.networking.vpn.h:15312. Slot 8 is RemoveAtEnd.</summary>
    internal static int ListRemoveAtBegin(IntPtr list, out IntPtr packetBuffer)
    {
        var value = default(IntPtr);
        var hr = ((delegate* unmanaged[Stdcall]<void*, void**, int>)(*(void***)list)[9])(
            (void*)list, (void**)&value);

        packetBuffer = value;
        return hr;
    }

    /// <summary>IVpnPacketBufferList slot 13, get_Size — windows.networking.vpn.h:15322.</summary>
    internal static int ListSize(IntPtr list, out uint size)
    {
        uint value = 0;
        var hr = ((delegate* unmanaged[Stdcall]<void*, uint*, int>)(*(void***)list)[13])(
            (void*)list, &value);

        size = value;
        return hr;
    }

    /// <summary>
    /// Gets an owned <c>IVpnChannel2</c> pointer from the projected channel.
    /// </summary>
    /// <remarks>
    /// The QI is mandatory, not defensive: the channel's default interface is <c>IVpnChannel</c>,
    /// whose slot 11 is <c>LogDiagnosticMessage(HSTRING)</c> — calling it with an out-pointer
    /// corrupts. This also serves as the connect-time self-check that the IID is right.
    /// </remarks>
    internal static int GetChannel2(VpnChannel channel, out IntPtr channel2)
    {
        var hr = QueryInterface(((IWinRTObject)channel).NativeObject.ThisPtr, in IID_IVpnChannel2, out channel2);

        // ThisPtr is borrowed from the projected object's reference; the object must stay alive
        // until the QI has taken its own.
        GC.KeepAlive(channel);
        return hr;
    }

    /// <summary>
    /// Gets an owned <c>IVpnPacketBufferList</c> pointer from a projected list, for one batch.
    /// </summary>
    /// <remarks>
    /// Owned rather than borrowed, deliberately: Encapsulate's cleanup itself makes raw calls on
    /// this pointer, and an owned reference makes the pointer's validity independent of when the
    /// garbage collector loses interest in the projected wrapper. One QI and one Release per
    /// batch is noise against the per-packet savings.
    /// </remarks>
    internal static int GetList(VpnPacketBufferList list, out IntPtr listPtr)
    {
        var hr = QueryInterface(((IWinRTObject)list).NativeObject.ThisPtr, in IID_IVpnPacketBufferList, out listPtr);
        GC.KeepAlive(list);
        return hr;
    }

    /// <summary>
    /// Resolves a packet buffer to its writable bytes: <c>get_Buffer</c>, the
    /// <c>IBufferByteAccess</c> QI, the byte pointer, and the capacity. All or nothing — on
    /// failure every intermediate reference has been released and the outs are zero.
    /// </summary>
    /// <remarks>
    /// The byte pointer is the packet's own memory and stays valid while the caller's
    /// <c>IVpnPacketBuffer</c> reference is held; <paramref name="buffer"/> and
    /// <paramref name="byteAccess"/> only need to live until the caller is done with the span and
    /// the length, then go to <see cref="ReleaseSpan"/>.
    /// </remarks>
    internal static int AcquireSpan(IntPtr packetBuffer, out IntPtr buffer, out IntPtr byteAccess, out byte* data, out uint capacity)
    {
        byteAccess = default;
        data = null;
        capacity = 0;

        var hr = GetBuffer(packetBuffer, out buffer);
        if (hr < 0)
        {
            buffer = default;
            return hr;
        }

        hr = QueryInterface(buffer, in IID_IBufferByteAccess, out byteAccess);
        if (hr < 0)
        {
            Release(buffer);
            buffer = default;
            byteAccess = default;
            return hr;
        }

        hr = GetBytes(byteAccess, out data);
        if (hr >= 0)
        {
            hr = GetCapacity(buffer, out capacity);
        }

        if (hr < 0)
        {
            ReleaseSpan(buffer, byteAccess);
            buffer = default;
            byteAccess = default;
            data = null;
            capacity = 0;
        }

        return hr;
    }

    /// <summary>Releases what <see cref="AcquireSpan"/> acquired. Zeros are tolerated.</summary>
    internal static void ReleaseSpan(IntPtr buffer, IntPtr byteAccess)
    {
        Release(byteAccess);
        Release(buffer);
    }

    /// <summary>
    /// One-time sanity check on the first packet of a direction: are these pointers the interfaces
    /// the slot table says they are?
    /// </summary>
    /// <remarks>
    /// Catches a wrong slot whose return is not an interface pointer at all — an uninitialized
    /// out-value, a property value misread as a pointer. What it cannot catch is a same-signature
    /// neighbor slot; only the header citations guard those.
    /// </remarks>
    internal static bool VerifyPacketShape(IntPtr packetBuffer, IntPtr buffer, uint capacity, out string why)
    {
        var hr = QueryInterface(packetBuffer, in IID_IVpnPacketBuffer, out var packetIdentity);
        if (hr < 0)
        {
            why = $"the packet pointer does not answer to IVpnPacketBuffer (0x{hr:X8})";
            return false;
        }

        Release(packetIdentity);

        hr = QueryInterface(buffer, in IID_IBuffer, out var bufferIdentity);
        if (hr < 0)
        {
            why = $"get_Buffer returned something that does not answer to IBuffer (0x{hr:X8})";
            return false;
        }

        Release(bufferIdentity);

        if (capacity is 0 or > 65536)
        {
            why = $"implausible buffer capacity {capacity}";
            return false;
        }

        why = string.Empty;
        return true;
    }

    /// <summary>Wraps a failing HRESULT for the paths that report through exceptions.</summary>
    internal static Exception FailureFor(int hr, string what)
    {
        return new InvalidOperationException($"{what} failed with 0x{hr:X8}", Marshal.GetExceptionForHR(hr));
    }
}
