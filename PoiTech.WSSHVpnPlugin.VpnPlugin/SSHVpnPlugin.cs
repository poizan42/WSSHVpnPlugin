using System;
using System.Collections.Generic;
using System.Text;
using Windows.Networking.Vpn;

namespace PoiTech.WSSHVpnPlugin.VpnPlugin;

public sealed class SSHVpnPlugin : IVpnPlugIn
{
    public void Connect(VpnChannel channel)
    {
        throw new NotImplementedException();
    }

    public void Decapsulate(VpnChannel channel, VpnPacketBuffer encapBuffer, VpnPacketBufferList decapsulatedPackets, VpnPacketBufferList controlPacketsToSend)
    {
        throw new NotImplementedException();
    }

    public void Disconnect(VpnChannel channel)
    {
        throw new NotImplementedException();
    }

    public void Encapsulate(VpnChannel channel, VpnPacketBufferList packets, VpnPacketBufferList encapulatedPackets)
    {
        throw new NotImplementedException();
    }

    public void GetKeepAlivePayload(VpnChannel channel, out VpnPacketBuffer keepAlivePacket)
    {
        throw new NotImplementedException();
    }
}
