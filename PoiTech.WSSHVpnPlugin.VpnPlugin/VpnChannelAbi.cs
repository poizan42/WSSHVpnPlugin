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
/// Each vtable below is a sequential struct whose fields are the function pointers in slot order,
/// transcribed member-for-member from the MIDL-generated headers in
/// <c>C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\winrt\</c> — not from memory or
/// intuition, because this family has traps: <c>GetVpnReceivePacketBuffer</c> is on
/// <c>IVpnChannel2</c>, not <c>IVpnChannel</c> (whose same-numbered slot is
/// <c>LogDiagnosticMessage</c>); <c>put_Status</c> precedes <c>get_Status</c> on
/// <c>IVpnPacketBuffer</c>; and <c>RemoveAtEnd</c> precedes <c>RemoveAtBegin</c> on
/// <c>IVpnPacketBufferList</c>. A wrong slot with the same signature cannot be caught at runtime,
/// so the struct layouts and their header citations are the review surface.
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

    // windows.networking.vpn.h:3663 — the interface carrying the out-of-band Append/Flush send
    // lane (UniversalApiContract 12.0).
    internal static readonly Guid IID_IVpnChannel5 = new("de7a0992-8384-4fbc-882c-1fd23124cd3b");

    // windows.networking.vpn.h:5097
    internal static readonly Guid IID_IVpnPacketBuffer = new("c2f891fc-4d5c-4a63-b70d-4e307eacce55");

    // windows.networking.vpn.h:5260
    internal static readonly Guid IID_IVpnPacketBufferList = new("c2f891fc-4d5c-4a63-b70d-4e307eacce77");

    // windows.storage.streams.h:1324 — ends 0fe0; IBufferByteAccess ends 0fef. One nibble apart.
    internal static readonly Guid IID_IBuffer = new("905a0fe0-bc53-11df-8c49-001e4fc686da");

    // robuffer.h:27
    internal static readonly Guid IID_IBufferByteAccess = new("905a0fef-bc53-11df-8c49-001e4fc686da");

    // windows.networking.vpn.h:15557 (vtable) — the interface the hand-rolled CCW implements.
    // One-transposition sibling of IVpnChannel's 4ac78d07-d1a8-4303-a091-c8d2e0915bc3; do not mix.
    internal static readonly Guid IID_IVpnPlugIn = new("ceb78d07-d0a8-4703-a091-c8c2c0915bc4");

    // windows.networking.vpn.h:12754 (vtable) — the statics factory carrying ProcessEventAsync.
    internal static readonly Guid IID_IVpnChannelStatics = new("88eb062d-e818-4ffd-98a6-363e3736c95d");

    /// <summary>
    /// The three <c>IUnknown</c> slots that prefix every COM vtable. The interface-specific vtables
    /// below embed this (via <see cref="InspectableVtable"/> for WinRT interfaces, directly for
    /// <see cref="BufferByteAccessVtable"/>), so the inheritance chain is visible as layout.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private readonly struct IUnknownVtable
    {
        private readonly IntPtr QueryInterfacePtr; // slot 0
        private readonly IntPtr AddRefPtr;         // slot 1
        private readonly IntPtr ReleasePtr;        // slot 2

        public int QueryInterface(IntPtr thisPtr, in Guid iid, out IntPtr result)
        {
            var value = default(IntPtr);
            int hr;

            fixed (Guid* riid = &iid)
            {
                hr = ((delegate* unmanaged[Stdcall]<void*, Guid*, void**, int>)QueryInterfacePtr)(
                    (void*)thisPtr, riid, (void**)&value);
            }

            result = value;
            return hr;
        }

        public uint Release(IntPtr thisPtr)
        {
            return ((delegate* unmanaged[Stdcall]<void*, uint>)ReleasePtr)((void*)thisPtr);
        }
    }

    /// <summary>The six slots that prefix every WinRT (IInspectable-derived) vtable.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private readonly struct InspectableVtable
    {
        private readonly IUnknownVtable IUnknown;       // slots 0-2
        private readonly IntPtr GetIidsPtr;             // slot 3
        private readonly IntPtr GetRuntimeClassNamePtr; // slot 4
        private readonly IntPtr GetTrustLevelPtr;       // slot 5
    }

    /// <summary>IVpnChannel2 — windows.networking.vpn.h:12095.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private readonly struct VpnChannel2Vtable
    {
        private readonly InspectableVtable IInspectable;      // slots 0-5
        private readonly IntPtr StartWithMainTransportPtr;    // slot 6
        private readonly IntPtr StartExistingTransportsPtr;   // slot 7
        private readonly IntPtr AddActivityStateChangePtr;    // slot 8, add_ActivityStateChange
        private readonly IntPtr RemoveActivityStateChangePtr; // slot 9, remove_ActivityStateChange
        private readonly IntPtr GetVpnSendPacketBufferPtr;    // slot 10
        private readonly IntPtr GetVpnReceivePacketBufferPtr; // slot 11

        public int GetVpnReceivePacketBuffer(IntPtr thisPtr, out IntPtr packetBuffer)
        {
            var value = default(IntPtr);
            var hr = ((delegate* unmanaged[Stdcall]<void*, void**, int>)GetVpnReceivePacketBufferPtr)(
                (void*)thisPtr, (void**)&value);

            packetBuffer = value;
            return hr;
        }

        public int GetVpnSendPacketBuffer(IntPtr thisPtr, out IntPtr packetBuffer)
        {
            var value = default(IntPtr);
            var hr = ((delegate* unmanaged[Stdcall]<void*, void**, int>)GetVpnSendPacketBufferPtr)(
                (void*)thisPtr, (void**)&value);

            packetBuffer = value;
            return hr;
        }
    }

    /// <summary>IVpnChannel5 — windows.networking.vpn.h:12317, the out-of-band Append/Flush lane.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private readonly struct VpnChannel5Vtable
    {
        private readonly InspectableVtable IInspectable;         // slots 0-5
        private readonly IntPtr AppendVpnReceivePacketBufferPtr; // slot 6, h:12333
        private readonly IntPtr AppendVpnSendPacketBufferPtr;    // slot 7, h:12335
        private readonly IntPtr FlushVpnReceivePacketBuffersPtr; // slot 8, h:12337
        private readonly IntPtr FlushVpnSendPacketBuffersPtr;    // slot 9, h:12338

        public int AppendVpnSendPacketBuffer(IntPtr thisPtr, IntPtr packetBuffer)
        {
            return ((delegate* unmanaged[Stdcall]<void*, void*, int>)AppendVpnSendPacketBufferPtr)(
                (void*)thisPtr, (void*)packetBuffer);
        }

        public int FlushVpnSendPacketBuffers(IntPtr thisPtr)
        {
            return ((delegate* unmanaged[Stdcall]<void*, int>)FlushVpnSendPacketBuffersPtr)(
                (void*)thisPtr);
        }
    }

    /// <summary>IVpnPacketBuffer — windows.networking.vpn.h:15001. put_Status precedes get_Status.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private readonly struct VpnPacketBufferVtable
    {
        private readonly InspectableVtable IInspectable;    // slots 0-5
        private readonly IntPtr GetBufferPtr;               // slot 6, get_Buffer
        private readonly IntPtr PutStatusPtr;               // slot 7, put_Status
        private readonly IntPtr GetStatusPtr;               // slot 8, get_Status
        private readonly IntPtr PutTransportAffinityPtr;    // slot 9, put_TransportAffinity
        private readonly IntPtr GetTransportAffinityPtr;    // slot 10, get_TransportAffinity

        public int GetBuffer(IntPtr thisPtr, out IntPtr buffer)
        {
            var value = default(IntPtr);
            var hr = ((delegate* unmanaged[Stdcall]<void*, void**, int>)GetBufferPtr)(
                (void*)thisPtr, (void**)&value);

            buffer = value;
            return hr;
        }

        public int GetTransportAffinity(IntPtr thisPtr, out uint affinity)
        {
            uint value = 0;
            var hr = ((delegate* unmanaged[Stdcall]<void*, uint*, int>)GetTransportAffinityPtr)(
                (void*)thisPtr, &value);

            affinity = value;
            return hr;
        }
    }

    /// <summary>IVpnPacketBufferList — windows.networking.vpn.h:15306. RemoveAtEnd precedes RemoveAtBegin.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private readonly struct VpnPacketBufferListVtable
    {
        private readonly InspectableVtable IInspectable; // slots 0-5
        private readonly IntPtr AppendPtr;               // slot 6
        private readonly IntPtr AddAtBeginPtr;           // slot 7
        private readonly IntPtr RemoveAtEndPtr;          // slot 8
        private readonly IntPtr RemoveAtBeginPtr;        // slot 9
        private readonly IntPtr ClearPtr;                // slot 10
        private readonly IntPtr PutStatusPtr;            // slot 11, put_Status
        private readonly IntPtr GetStatusPtr;            // slot 12, get_Status
        private readonly IntPtr GetSizePtr;              // slot 13, get_Size

        public int Append(IntPtr thisPtr, IntPtr packetBuffer)
        {
            return ((delegate* unmanaged[Stdcall]<void*, void*, int>)AppendPtr)(
                (void*)thisPtr, (void*)packetBuffer);
        }

        public int RemoveAtBegin(IntPtr thisPtr, out IntPtr packetBuffer)
        {
            var value = default(IntPtr);
            var hr = ((delegate* unmanaged[Stdcall]<void*, void**, int>)RemoveAtBeginPtr)(
                (void*)thisPtr, (void**)&value);

            packetBuffer = value;
            return hr;
        }

        public int GetSize(IntPtr thisPtr, out uint size)
        {
            uint value = 0;
            var hr = ((delegate* unmanaged[Stdcall]<void*, uint*, int>)GetSizePtr)(
                (void*)thisPtr, &value);

            size = value;
            return hr;
        }
    }

    /// <summary>IBuffer — windows.storage.streams.h:4140.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private readonly struct BufferVtable
    {
        private readonly InspectableVtable IInspectable; // slots 0-5
        private readonly IntPtr GetCapacityPtr;          // slot 6, get_Capacity
        private readonly IntPtr GetLengthPtr;            // slot 7, get_Length
        private readonly IntPtr PutLengthPtr;            // slot 8, put_Length

        public int GetCapacity(IntPtr thisPtr, out uint capacity)
        {
            uint value = 0;
            var hr = ((delegate* unmanaged[Stdcall]<void*, uint*, int>)GetCapacityPtr)(
                (void*)thisPtr, &value);

            capacity = value;
            return hr;
        }

        public int GetLength(IntPtr thisPtr, out uint length)
        {
            uint value = 0;
            var hr = ((delegate* unmanaged[Stdcall]<void*, uint*, int>)GetLengthPtr)(
                (void*)thisPtr, &value);

            length = value;
            return hr;
        }

        public int PutLength(IntPtr thisPtr, uint length)
        {
            return ((delegate* unmanaged[Stdcall]<void*, uint, int>)PutLengthPtr)(
                (void*)thisPtr, length);
        }
    }

    /// <summary>
    /// IBufferByteAccess — robuffer.h:27. Derives from IUnknown, not IInspectable — the embedded
    /// three-slot head (where every other vtable here embeds the six-slot one) is why its first
    /// method is slot 3, not 6.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private readonly struct BufferByteAccessVtable
    {
        private readonly IUnknownVtable IUnknown; // slots 0-2
        private readonly IntPtr BufferPtr;        // slot 3, Buffer

        public int Buffer(IntPtr thisPtr, out byte* data)
        {
            byte* value = null;
            var hr = ((delegate* unmanaged[Stdcall]<void*, byte**, int>)BufferPtr)(
                (void*)thisPtr, &value);

            data = value;
            return hr;
        }
    }

    /// <summary>IVpnChannelStatics — windows.networking.vpn.h:12754.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private readonly struct VpnChannelStaticsVtable
    {
        private readonly InspectableVtable IInspectable; // slots 0-5
        private readonly IntPtr ProcessEventAsyncPtr;    // slot 6, ProcessEventAsync(IInspectable* thirdPartyPlugIn, IInspectable* event)

        public int ProcessEventAsync(IntPtr thisPtr, IntPtr plugIn, IntPtr thirdPartyEvent)
        {
            return ((delegate* unmanaged[Stdcall]<void*, void*, void*, int>)ProcessEventAsyncPtr)(
                (void*)thisPtr, (void*)plugIn, (void*)thirdPartyEvent);
        }
    }

    /// <summary>IVpnChannelStatics slot 6 — dispatches one activation's event to the plug-in.</summary>
    internal static int ProcessEvent(IntPtr statics, IntPtr plugIn, IntPtr thirdPartyEvent)
        => (*(VpnChannelStaticsVtable**)statics)->ProcessEventAsync(statics, plugIn, thirdPartyEvent);

    /// <summary>IUnknown slot 0.</summary>
    internal static int QueryInterface(IntPtr ptr, in Guid iid, out IntPtr result)
        => (*(IUnknownVtable**)ptr)->QueryInterface(ptr, in iid, out result);

    /// <summary>IUnknown slot 2. Tolerates zero so cleanup paths need no guards.</summary>
    internal static void Release(IntPtr ptr)
    {
        if (ptr == default)
        {
            return;
        }

        _ = (*(IUnknownVtable**)ptr)->Release(ptr);
    }

    /// <summary>IVpnChannel2 slot 11. Slot 10 is GetVpnSendPacketBuffer.</summary>
    internal static int GetReceiveBuffer(IntPtr channel2, out IntPtr packetBuffer)
        => (*(VpnChannel2Vtable**)channel2)->GetVpnReceivePacketBuffer(channel2, out packetBuffer);

    /// <summary>
    /// IVpnChannel2 slot 10. Same-index trap, both directions load-bearing: IVpnChannel's slots
    /// 10/11 are RequestVpnPacketBuffer/LogDiagnosticMessage, IVpnChannel2's are the
    /// GetVpnSendPacketBuffer/GetVpnReceivePacketBuffer pair.
    /// </summary>
    internal static int GetSendBuffer(IntPtr channel2, out IntPtr packetBuffer)
        => (*(VpnChannel2Vtable**)channel2)->GetVpnSendPacketBuffer(channel2, out packetBuffer);

    /// <summary>IVpnChannel5 slot 7. The channel takes its own reference; the caller's must still be released.</summary>
    internal static int AppendSendBuffer(IntPtr channel5, IntPtr packetBuffer)
        => (*(VpnChannel5Vtable**)channel5)->AppendVpnSendPacketBuffer(channel5, packetBuffer);

    /// <summary>IVpnChannel5 slot 9. Transmits everything appended since the last flush, in append order.</summary>
    internal static int FlushSendBuffers(IntPtr channel5)
        => (*(VpnChannel5Vtable**)channel5)->FlushVpnSendPacketBuffers(channel5);

    /// <summary>IVpnPacketBuffer slot 6, get_Buffer.</summary>
    internal static int GetBuffer(IntPtr packetBuffer, out IntPtr buffer)
        => (*(VpnPacketBufferVtable**)packetBuffer)->GetBuffer(packetBuffer, out buffer);

    /// <summary>
    /// IVpnPacketBuffer slot 10, get_TransportAffinity — which of the two associated transports a
    /// delivered buffer arrived on, and the discriminator between SSH wire bytes (main) and
    /// doorbell datagrams (optional).
    /// </summary>
    internal static int GetTransportAffinity(IntPtr packetBuffer, out uint affinity)
        => (*(VpnPacketBufferVtable**)packetBuffer)->GetTransportAffinity(packetBuffer, out affinity);

    /// <summary>IBuffer slot 6, get_Capacity.</summary>
    internal static int GetCapacity(IntPtr buffer, out uint capacity)
        => (*(BufferVtable**)buffer)->GetCapacity(buffer, out capacity);

    /// <summary>IBuffer slot 7, get_Length.</summary>
    internal static int GetLength(IntPtr buffer, out uint length)
        => (*(BufferVtable**)buffer)->GetLength(buffer, out length);

    /// <summary>IBuffer slot 8, put_Length.</summary>
    internal static int SetLength(IntPtr buffer, uint length)
        => (*(BufferVtable**)buffer)->PutLength(buffer, length);

    /// <summary>IBufferByteAccess slot 3, Buffer.</summary>
    internal static int GetBytes(IntPtr byteAccess, out byte* data)
        => (*(BufferByteAccessVtable**)byteAccess)->Buffer(byteAccess, out data);

    /// <summary>IVpnPacketBufferList slot 6, Append. The list takes its own reference.</summary>
    internal static int ListAppend(IntPtr list, IntPtr packetBuffer)
        => (*(VpnPacketBufferListVtable**)list)->Append(list, packetBuffer);

    /// <summary>IVpnPacketBufferList slot 9, RemoveAtBegin. Slot 8 is RemoveAtEnd.</summary>
    internal static int ListRemoveAtBegin(IntPtr list, out IntPtr packetBuffer)
        => (*(VpnPacketBufferListVtable**)list)->RemoveAtBegin(list, out packetBuffer);

    /// <summary>IVpnPacketBufferList slot 13, get_Size.</summary>
    internal static int ListSize(IntPtr list, out uint size)
        => (*(VpnPacketBufferListVtable**)list)->GetSize(list, out size);

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
    /// Gets an owned <c>IVpnChannel5</c> pointer from the projected channel — the out-of-band
    /// send lane the platform-owned transport writes through.
    /// </summary>
    internal static int GetChannel5(VpnChannel channel, out IntPtr channel5)
    {
        var hr = QueryInterface(((IWinRTObject)channel).NativeObject.ThisPtr, in IID_IVpnChannel5, out channel5);
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
    /// Resolves a packet buffer to its readable bytes: like <see cref="AcquireSpan"/> but with the
    /// buffer's <c>Length</c> — the bytes actually carried — instead of its capacity. All or
    /// nothing; release with <see cref="ReleaseSpan"/>.
    /// </summary>
    internal static int AcquireReadSpan(IntPtr packetBuffer, out IntPtr buffer, out IntPtr byteAccess, out byte* data, out uint length)
    {
        byteAccess = default;
        data = null;
        length = 0;

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
            hr = GetLength(buffer, out length);
        }

        if (hr < 0)
        {
            ReleaseSpan(buffer, byteAccess);
            buffer = default;
            byteAccess = default;
            data = null;
            length = 0;
        }

        return hr;
    }

    /// <summary>
    /// One-time sanity check on the first packet of a direction: are these pointers the interfaces
    /// the slot table says they are?
    /// </summary>
    /// <remarks>
    /// Catches a wrong slot whose return is not an interface pointer at all — an uninitialized
    /// out-value, a property value misread as a pointer. What it cannot catch is a same-signature
    /// neighbor slot; only the vtable structs and their header citations guard those.
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
