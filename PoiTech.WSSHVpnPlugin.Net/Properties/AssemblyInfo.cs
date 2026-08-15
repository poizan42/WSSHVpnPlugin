using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("PoiTech.WSSHVpnPlugin.Net.Tests")]

// The plug-in drives the stack; the parsing types stay internal rather than becoming public API of
// a library with exactly one consumer.
[assembly: InternalsVisibleTo("PoiTech.WSSHVpnPlugin.VpnPlugin")]
