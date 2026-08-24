using System;
using System.Collections.Generic;
using System.Xml.Linq;

namespace PoiTech.WSSHVpnPlugin.Net;

/// <summary>
/// The saved-connections document: per-server configuration entries matched by host name.
/// </summary>
/// <remarks>
/// <para>
/// A profile created in Windows Settings carries no usable custom configuration — the dialog offers
/// only a name, a server and sign-in info — and the platform gives the owning package no way to
/// write one into it afterwards, because Settings profiles are user-scoped. So the configuration
/// lives outside the profile, in a document the app edits and the plug-in reads at connect, and the
/// server name is the join key: whatever the profile names as its server selects the entry, the way
/// a host name selects a block in OpenSSH's client configuration.
/// </para>
/// <para>
/// Entries are <c>&lt;SshVpnConfiguration&gt;</c> elements — exactly the fragment a profile would
/// otherwise embed, plus the <c>&lt;Host&gt;</c> that keys it — so one reader serves both sources.
/// Matching is exact and case-insensitive; nothing here does I/O, so both the matching and the
/// editing are exercised in the fast loop, and the two processes that share the file cannot drift
/// on what "matches" means.
/// </para>
/// </remarks>
internal static class ConnectionsFile
{
    /// <summary>The file name, relative to the package's local folder.</summary>
    public const string FileName = "connections.xml";

    public const string RootElementName = "SshVpnConnections";

    /// <summary>Deliberately the custom configuration's root name: an entry is one of those.</summary>
    public const string EntryElementName = "SshVpnConfiguration";

    private const string HostElementName = "Host";

    public static XElement NewRoot() => new(RootElementName);

    /// <summary>
    /// Parses the document, refusing anything that is not a connections file.
    /// </summary>
    /// <exception cref="FormatException">The text is not well-formed XML, or the root is wrong.</exception>
    public static XElement Parse(string text)
    {
        XElement root;
        try
        {
            root = XDocument.Parse(text).Root
                ?? throw new FormatException($"{FileName} is empty.");
        }
        catch (System.Xml.XmlException ex)
        {
            throw new FormatException($"{FileName} is not well-formed XML.", ex);
        }

        if (root.Name.LocalName != RootElementName)
        {
            throw new FormatException(
                $"{FileName} must have a <{RootElementName}> root element but has <{root.Name.LocalName}>.");
        }

        return root;
    }

    /// <summary>
    /// Finds the first entry whose <c>&lt;Host&gt;</c> matches, or <see langword="null"/>.
    /// </summary>
    public static XElement? FindEntry(XElement root, string host)
    {
        ArgumentNullException.ThrowIfNull(root);
        ArgumentNullException.ThrowIfNull(host);

        foreach (var entry in root.Elements(EntryElementName))
        {
            if (Matches(HostOf(entry), host))
            {
                return entry;
            }
        }

        return null;
    }

    /// <summary>
    /// Replaces the entry with the same host, or appends when there is none.
    /// </summary>
    public static void Upsert(XElement root, XElement entry)
    {
        ArgumentNullException.ThrowIfNull(root);
        ArgumentNullException.ThrowIfNull(entry);

        var host = HostOf(entry)
            ?? throw new ArgumentException($"The entry has no <{HostElementName}> to key it by.", nameof(entry));

        if (FindEntry(root, host) is { } existing)
        {
            existing.ReplaceWith(entry);
        }
        else
        {
            root.Add(entry);
        }
    }

    /// <summary>
    /// Removes the entry with the given host. Returns whether one was there to remove.
    /// </summary>
    public static bool Remove(XElement root, string host)
    {
        if (FindEntry(root, host) is { } entry)
        {
            entry.Remove();
            return true;
        }

        return false;
    }

    /// <summary>
    /// Gets the entry's host, or <see langword="null"/> for an entry that has none.
    /// </summary>
    public static string? HostOf(XElement entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        var host = entry.Element(HostElementName)?.Value.Trim();
        return string.IsNullOrEmpty(host) ? null : host;
    }

    /// <summary>
    /// Lists the hosts of every keyed entry, in document order.
    /// </summary>
    public static List<string> Hosts(XElement root)
    {
        ArgumentNullException.ThrowIfNull(root);

        var hosts = new List<string>();
        foreach (var entry in root.Elements(EntryElementName))
        {
            if (HostOf(entry) is { } host)
            {
                hosts.Add(host);
            }
        }

        return hosts;
    }

    /// <summary>
    /// Host names are case-insensitive, and nothing here is locale text — hence ordinal.
    /// </summary>
    private static bool Matches(string? entryHost, string host)
        => entryHost is not null
            && string.Equals(entryHost, host.Trim(), StringComparison.OrdinalIgnoreCase);
}
