// MIT License
//
// Copyright (c) 2023-Present - Violet Hansen - (aka HotCakeX on GitHub) - Email Address: spynetgirl@outlook.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// See here for more information: https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE
//

using System.Collections.Concurrent;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text.Json;
using System.Threading;

namespace HardenSystemSecurity.DNS;

/// <summary>
/// Counts how many times each domain name was queried through a DNS server of the DNS page and keeps the
/// counts in a file. The file is a JSON object that maps every domain name to its count, for example
/// <c>{ "example.com": 12, "www.example.org": 3 }</c>, ordered from the most to the least queried domain.
/// An existing file is loaded when the log is opened, so the counts keep growing across runs.
/// When only root domains are logged, every name is counted under its registrable domain, for example
/// <c>azure.homefront.microsoft.com</c> under <c>microsoft.com</c>.
/// </summary>
internal sealed partial class DnsDomainLog : IDisposable
{
	/// <summary>
	/// The most distinct domain names that are kept. It bounds the memory and the file size when clients
	/// query endless random names; names beyond the limit are not counted.
	/// </summary>
	private const int MaximumDomains = 200000;

	/// <summary>
	/// How often the counts are written to the file while they are changing.
	/// </summary>
	private static readonly TimeSpan SaveInterval = TimeSpan.FromSeconds(5);

	private static readonly JsonWriterOptions WriterOptions = new() { Indented = true };

	/// <summary>
	/// Second-level labels that country code top-level domains commonly use for registrations, such as <c>co.uk</c> or <c>com.au</c>.
	/// A name under one of them keeps three labels as its root domain instead of two.
	/// </summary>
	private static readonly FrozenSet<string> CountrySecondLevelLabels = FrozenSet.Create(
		StringComparer.OrdinalIgnoreCase,
		"ac", "co", "com", "edu", "gob", "go", "gov", "govt", "ltd", "mil", "ne", "net", "nhs", "nic", "or", "org", "plc", "police", "sch");

	private static readonly FrozenSet<string>.AlternateLookup<ReadOnlySpan<char>> CountrySecondLevelLabelsLookup = CountrySecondLevelLabels.GetAlternateLookup<ReadOnlySpan<char>>();

	private readonly ConcurrentDictionary<string, long> Counts = new(StringComparer.OrdinalIgnoreCase);
	private readonly Action<string> WriteLine;
	private readonly Lock SaveLock = new();
	private readonly Timer SaveTimer;

	// Whether every name is counted under its root domain instead of the full name.
	private readonly bool RootDomainsOnly;

	// 1 when the counts changed since they were last written to the file.
	private int HasUnsavedChanges;

	// 1 once the domain limit was reported in the logs, so it is reported only once.
	private int LimitReported;
	private int Disposed;

	/// <summary>
	/// The file that the counts are saved to.
	/// </summary>
	internal string FilePath { get; }

	private DnsDomainLog(string filePath, bool rootDomainsOnly, Action<string> writeLine)
	{
		FilePath = filePath;
		RootDomainsOnly = rootDomainsOnly;
		WriteLine = writeLine;
		SaveTimer = new Timer(static state => ((DnsDomainLog)state!).Save(), this, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
	}

	/// <summary>
	/// Opens the log and loads the counts of an existing file. An empty or missing file starts an empty log.
	/// A file with any other content is rejected, so a file selected by mistake is never overwritten.
	/// </summary>
	/// <param name="rootDomainsOnly">Whether every name is counted under its root domain, such as <c>microsoft.com</c> for <c>azure.homefront.microsoft.com</c>.</param>
	internal static DnsDomainLog Open(string filePath, bool rootDomainsOnly, Action<string> writeLine)
	{
		string fullPath = Path.GetFullPath(filePath);
		DnsDomainLog log = new(fullPath, rootDomainsOnly, writeLine);
		try
		{
			log.Load();

			// Writing the file right away proves that the location is writable before the server starts.
			log.Save(force: true);
			_ = log.SaveTimer.Change(SaveInterval, SaveInterval);
			return log;
		}
		catch
		{
			log.SaveTimer.Dispose();
			throw;
		}
	}

	/// <summary>
	/// Counts one query for the domain name. Called by the servers from any thread.
	/// </summary>
	internal void Record(string domain)
	{
		// A trailing dot only marks the name as fully qualified, and the root name itself is not a domain.
		// The names are stored in lower case, which is how the same domain is written by every client.
		string name = DnsMessage.ToLowerCaseName(domain.TrimEnd('.'));
		if (name.Length == 0)
		{
			return;
		}
		if (RootDomainsOnly)
		{
			name = GetRootDomain(name);
		}
		if (!Counts.ContainsKey(name) && Counts.Count >= MaximumDomains)
		{
			if (Interlocked.Exchange(ref LimitReported, 1) == 0)
			{
				WriteLine($"DOMAIN LOG LIMIT REACHED file={FilePath} domains={MaximumDomains}; new domain names are no longer counted");
			}
			return;
		}
		_ = Counts.AddOrUpdate(name, 1, static (_, count) => count + 1);
		_ = Interlocked.Exchange(ref HasUnsavedChanges, 1);
	}

	/// <summary>
	/// Returns the root (registrable) domain of a name: its last two labels, or its last three labels under a common
	/// second-level domain of a country code top-level domain, such as <c>bbc.co.uk</c> for <c>www.bbc.co.uk</c>.
	/// Names with fewer labels and IP addresses are returned unchanged.
	/// </summary>
	internal static string GetRootDomain(string name)
	{
		// Searching a prefix span returns the same index the dot has in the whole name.
		int lastDot = name.AsSpan().LastIndexOf('.');
		if (lastDot <= 0)
		{
			return name;
		}
		int secondLastDot = name.AsSpan(0, lastDot).LastIndexOf('.');
		if (secondLastDot < 0 || IPAddress.TryParse(name, out _))
		{
			return name;
		}
		ReadOnlySpan<char> topLevelLabel = name.AsSpan(lastDot + 1);
		ReadOnlySpan<char> secondLevelLabel = name.AsSpan(secondLastDot + 1, lastDot - secondLastDot - 1);
		if (topLevelLabel.Length == 2 && CountrySecondLevelLabelsLookup.Contains(secondLevelLabel))
		{
			int thirdLastDot = name.AsSpan(0, secondLastDot).LastIndexOf('.');
			return thirdLastDot < 0 ? name : name[(thirdLastDot + 1)..];
		}
		return name[(secondLastDot + 1)..];
	}

	private void Load()
	{
		if (!File.Exists(FilePath))
		{
			return;
		}
		byte[] content = File.ReadAllBytes(FilePath);

		// A UTF-8 byte order mark is not part of the JSON text, and a file that only has white space is treated as empty.
		ReadOnlyMemory<byte> json = content.AsSpan().StartsWith("\uFEFF"u8) ? content.AsMemory(3) : content;
		if (json.Span.Trim(" \t\r\n"u8).IsEmpty)
		{
			return;
		}
		try
		{
			using JsonDocument document = JsonDocument.Parse(json);
			if (document.RootElement.ValueKind != JsonValueKind.Object)
			{
				throw new InvalidDataException($"'{FilePath}' is not a domain log. Select a new file or a file that the Harden System Security app created.");
			}
			foreach (JsonProperty property in document.RootElement.EnumerateObject())
			{
				if (property.Value.ValueKind != JsonValueKind.Number || !property.Value.TryGetInt64(out long count) || count < 0)
				{
					throw new InvalidDataException($"'{FilePath}' is not a domain log. Select a new file or a file that the Harden System Security app created.");
				}
				Counts[property.Name] = count;
			}
		}
		catch (JsonException exception)
		{
			throw new InvalidDataException($"'{FilePath}' is not a domain log. Select a new file or a file that the Harden System Security app created.", exception);
		}
	}

	// Called by the timer. A failure is logged and the next tick tries again, because the counts stay in memory.
	private void Save() => Save(force: false);

	private void Save(bool force)
	{
		lock (SaveLock)
		{
			if (Interlocked.Exchange(ref HasUnsavedChanges, 0) == 0 && !force)
			{
				return;
			}
			try
			{
				List<KeyValuePair<string, long>> entries = [.. Counts];

				// The most queried domains come first; domains with the same count are ordered by name.
				entries.Sort(static (left, right) =>
				{
					int byCount = right.Value.CompareTo(left.Value);
					return byCount != 0 ? byCount : StringComparer.OrdinalIgnoreCase.Compare(left.Key, right.Key);
				});

				// The new content is written next to the file and then swapped in, so the file is never left half written.
				string temporaryPath = FilePath + ".tmp";
				using (FileStream stream = new(temporaryPath, FileMode.Create, FileAccess.Write, FileShare.None))
				using (Utf8JsonWriter writer = new(stream, WriterOptions))
				{
					writer.WriteStartObject();
					foreach (KeyValuePair<string, long> entry in entries)
					{
						writer.WriteNumber(entry.Key, entry.Value);
					}
					writer.WriteEndObject();
				}
				File.Move(temporaryPath, FilePath, true);
			}
			catch (Exception exception)
			{
				// The changes are still unsaved, so the next save writes them. An exception must not escape
				// from the timer's thread, where it would end the whole app.
				_ = Interlocked.Exchange(ref HasUnsavedChanges, 1);
				if (force)
				{
					throw;
				}
				WriteLine($"DOMAIN LOG SAVE FAILURE file={FilePath} error:{exception.Message}");
			}
		}
	}

	/// <summary>
	/// Stops the periodic saving and writes the latest counts to the file.
	/// </summary>
	public void Dispose()
	{
		if (Interlocked.Exchange(ref Disposed, 1) != 0)
		{
			return;
		}

		// A save that the timer already started finishes first, because every save takes the same lock.
		SaveTimer.Dispose();
		Save(force: false);
		WriteLine($"DOMAIN LOG SAVED file={FilePath} domains={Counts.Count}");
	}
}
