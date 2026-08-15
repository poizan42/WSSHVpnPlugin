using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using Windows.Networking.Vpn;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

/// <summary>
/// Direct access to the bytes of a <see cref="VpnPacketBuffer"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="VpnPacketBuffer.Buffer"/> is a concrete <c>Windows.Storage.Streams.Buffer</c> exposing
/// only <c>Capacity</c> and <c>Length</c>. The <c>AsBuffer</c> / <c>ToArray</c> extensions that used
/// to bridge it do not exist on modern .NET, and <c>DataWriter</c> cannot fill an existing buffer in
/// place — it builds its own. So the only way to write a packet without copying it twice is to take
/// a pointer, which is what <c>IMemoryBufferByteAccess</c> is for.
/// </para>
/// <para>
/// This runs per packet, so it must not allocate.
/// </para>
/// </remarks>
internal static class VpnPacketBufferAccess
{
    /// <summary>
    /// Gets a span over the whole capacity of the packet's buffer.
    /// </summary>
    /// <param name="packet">The packet buffer to access.</param>
    /// <returns>
    /// A span covering <c>Buffer.Capacity</c> bytes. Set <c>Buffer.Length</c> to the number of bytes
    /// actually written before handing the packet back to the platform.
    /// </returns>
    public static unsafe Span<byte> GetSpan(Windows.Storage.Streams.IBuffer buffer)
    {
        ArgumentNullException.ThrowIfNull(buffer);

        // The pointer comes from the buffer itself, not from wrapping it. The first version
        // created a MemoryBuffer over the IBuffer and a reference over that - two new WinRT
        // objects per packet - and each creation resolved the object's runtime class name, which
        // failed inside WinTypes and fired RoOriginateError, whose reporting captures diagnostics
        // through the registry. About a millisecond per packet, all of it overhead: one core
        // saturated at ~900 packets/s, which is the 1.2 MB/s ceiling every download hit while
        // every window and queue above measured healthy. Caught red-handed by sampling the hot
        // thread. IBufferByteAccess is the same pointer with a single QueryInterface on the object
        // already in hand.
        ((IBufferByteAccess)(object)buffer).GetBuffer(out var data);

        return new Span<byte>(data, checked((int)buffer.Capacity));
    }
}

/// <summary>
/// Hands back the raw pointer behind an <c>IBuffer</c>.
/// </summary>
/// <remarks>
/// Declared here because the SDK's own <c>IBufferByteAccess</c> is not public in the projection.
/// Source-generated rather than <c>[ComImport]</c>: this assembly sets
/// <c>DisableRuntimeMarshalling</c> and is published Native AOT, where the built-in COM marshaller
/// is not something to rely on.
/// </remarks>
[GeneratedComInterface]
[Guid("905a0fef-bc53-11df-8c49-001e4fc686da")]
internal unsafe partial interface IBufferByteAccess
{
    /// <summary>
    /// Gets the address of the underlying memory, valid for the buffer's capacity.
    /// </summary>
    /// <param name="buffer">Receives the address of the first byte.</param>
    void GetBuffer(out byte* buffer);
}
