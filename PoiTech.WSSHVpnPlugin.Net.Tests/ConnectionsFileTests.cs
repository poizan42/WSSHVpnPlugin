using System;
using System.Xml.Linq;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using PoiTech.WSSHVpnPlugin.Net;

namespace PoiTech.WSSHVpnPlugin.Net.Tests;

/// <summary>
/// Matching and editing of the saved-connections document.
/// </summary>
/// <remarks>
/// Two processes share this file — the app writes it, the plug-in reads it at connect — and the
/// contract between them is "the entry for this host". These pin that contract: what matches, what
/// an upsert replaces, and what a document that is not a connections file does.
/// </remarks>
[TestClass]
public class ConnectionsFileTests
{
    private static XElement Entry(string host, string? user = null)
    {
        var entry = new XElement(ConnectionsFile.EntryElementName, new XElement("Host", host));
        if (user is not null)
        {
            entry.Add(new XElement("UserName", user));
        }

        return entry;
    }

    private static XElement Root(params XElement[] entries)
    {
        var root = ConnectionsFile.NewRoot();
        foreach (var entry in entries)
        {
            root.Add(entry);
        }

        return root;
    }

    [TestMethod]
    public void FindsAnExactMatch()
    {
        var root = Root(Entry("a.example.com"), Entry("b.example.com", "alice"));

        var entry = ConnectionsFile.FindEntry(root, "b.example.com");

        Assert.IsNotNull(entry);
        Assert.AreEqual("alice", entry.Element("UserName")?.Value);
    }

    [TestMethod]
    public void MatchingIgnoresCaseAndSurroundingWhitespace()
    {
        var root = Root(Entry(" Server.Example.COM "));

        Assert.IsNotNull(ConnectionsFile.FindEntry(root, "server.example.com"));
        Assert.IsNotNull(ConnectionsFile.FindEntry(root, "  SERVER.EXAMPLE.COM"));
    }

    [TestMethod]
    public void NoMatchIsNull()
    {
        var root = Root(Entry("a.example.com"));

        Assert.IsNull(ConnectionsFile.FindEntry(root, "b.example.com"));
        Assert.IsNull(ConnectionsFile.FindEntry(ConnectionsFile.NewRoot(), "a.example.com"));
    }

    [TestMethod]
    public void AKeylessEntryMatchesNothing()
    {
        // Not even the empty string: an entry without a host is unaddressable, not a wildcard.
        var keyless = new XElement(ConnectionsFile.EntryElementName, new XElement("UserName", "alice"));
        var root = Root(keyless);

        Assert.IsNull(ConnectionsFile.FindEntry(root, ""));
        Assert.IsNull(ConnectionsFile.FindEntry(root, "a.example.com"));
        CollectionAssert.AreEqual(Array.Empty<string>(), ConnectionsFile.Hosts(root));
    }

    [TestMethod]
    public void DuplicateHostsResolveToTheFirst()
    {
        var root = Root(Entry("a.example.com", "first"), Entry("A.EXAMPLE.COM", "second"));

        Assert.AreEqual("first", ConnectionsFile.FindEntry(root, "a.example.com")?.Element("UserName")?.Value);
    }

    [TestMethod]
    public void UpsertReplacesInPlace()
    {
        var root = Root(Entry("a.example.com", "old"), Entry("b.example.com"));

        ConnectionsFile.Upsert(root, Entry("A.example.com", "new"));

        CollectionAssert.AreEqual(
            new[] { "A.example.com", "b.example.com" },
            ConnectionsFile.Hosts(root));
        Assert.AreEqual("new", ConnectionsFile.FindEntry(root, "a.example.com")?.Element("UserName")?.Value);
    }

    [TestMethod]
    public void UpsertAppendsWhenAbsent()
    {
        var root = Root(Entry("a.example.com"));

        ConnectionsFile.Upsert(root, Entry("b.example.com"));

        CollectionAssert.AreEqual(new[] { "a.example.com", "b.example.com" }, ConnectionsFile.Hosts(root));
    }

    [TestMethod]
    public void UpsertRefusesAKeylessEntry()
    {
        var keyless = new XElement(ConnectionsFile.EntryElementName);

        Assert.ThrowsException<ArgumentException>(() => ConnectionsFile.Upsert(ConnectionsFile.NewRoot(), keyless));
    }

    [TestMethod]
    public void RemoveReportsWhetherAnythingWasThere()
    {
        var root = Root(Entry("a.example.com"), Entry("b.example.com"));

        Assert.IsTrue(ConnectionsFile.Remove(root, "A.EXAMPLE.COM"));
        Assert.IsFalse(ConnectionsFile.Remove(root, "a.example.com"));
        CollectionAssert.AreEqual(new[] { "b.example.com" }, ConnectionsFile.Hosts(root));
    }

    [TestMethod]
    public void ParseRoundTrips()
    {
        var root = Root(Entry("a.example.com", "alice"));

        var reread = ConnectionsFile.Parse(root.ToString(SaveOptions.DisableFormatting));

        Assert.AreEqual("alice", ConnectionsFile.FindEntry(reread, "a.example.com")?.Element("UserName")?.Value);
    }

    [TestMethod]
    public void ParseRefusesTheWrongRootAndNonXml()
    {
        Assert.ThrowsException<FormatException>(() => ConnectionsFile.Parse("<SshVpnConfiguration />"));
        Assert.ThrowsException<FormatException>(() => ConnectionsFile.Parse("not xml"));
    }
}
