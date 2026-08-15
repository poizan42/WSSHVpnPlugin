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
    public static unsafe Span<byte> GetSpan(VpnPacketBuffer packet)
    {
        ArgumentNullException.ThrowIfNull(packet);

        var buffer = packet.Buffer;

        // The MemoryBuffer and its reference only wrap the existing IBuffer; disposing them does not
        // touch the underlying memory, which the platform owns.
        using var memoryBuffer = Windows.Storage.Streams.Buffer.CreateMemoryBufferOverIBuffer(buffer);
        using var reference = memoryBuffer.CreateReference();

        ((IMemoryBufferByteAccess)(object)reference).GetBuffer(out var data, out var capacity);

        return new Span<byte>(data, checked((int)capacity));
    }
}

/// <summary>
/// Hands back the raw pointer behind an <c>IMemoryBufferReference</c>.
/// </summary>
/// <remarks>
/// Declared here because the SDK's own <c>IBufferByteAccess</c> is not public in the projection.
/// Source-generated rather than <c>[ComImport]</c>: this assembly sets
/// <c>DisableRuntimeMarshalling</c> and is published Native AOT, where the built-in COM marshaller
/// is not something to rely on.
/// </remarks>
[GeneratedComInterface]
[Guid("5b0d3235-4dba-4d44-865e-8f1d0e4fd04d")]
internal unsafe partial interface IMemoryBufferByteAccess
{
    /// <summary>
    /// Gets the address and capacity of the underlying memory.
    /// </summary>
    /// <param name="buffer">Receives the address of the first byte.</param>
    /// <param name="capacity">Receives the number of bytes available.</param>
    void GetBuffer(out byte* buffer, out uint capacity);
}
