using System;

namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// The TCP control bits.
/// </summary>
[Flags]
internal enum TcpFlags : byte
{
    /// <summary>No flags.</summary>
    None = 0,

    /// <summary>FIN: the sender has finished sending.</summary>
    Fin = 1 << 0,

    /// <summary>SYN: synchronise sequence numbers.</summary>
    Syn = 1 << 1,

    /// <summary>RST: reset the connection.</summary>
    Rst = 1 << 2,

    /// <summary>PSH: push buffered data to the application.</summary>
    Psh = 1 << 3,

    /// <summary>ACK: the acknowledgement field is significant.</summary>
    Ack = 1 << 4,

    /// <summary>URG: the urgent pointer is significant.</summary>
    Urg = 1 << 5,
}
