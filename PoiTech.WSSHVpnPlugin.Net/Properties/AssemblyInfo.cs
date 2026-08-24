using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("PoiTech.WSSHVpnPlugin.Net.Tests")]

// The plug-in drives the stack; the parsing types stay internal rather than becoming public API of
// a library with exactly one consumer.
[assembly: InternalsVisibleTo("PoiTech.WSSHVpnPlugin.VpnPlugin")]

// The app shares ConnectionsFile with the plug-in, so the two processes that read and write the
// saved-connections document cannot disagree on what "the entry for this host" means.
[assembly: InternalsVisibleTo("PoiTech.WSSHVpnPlugin.App")]
