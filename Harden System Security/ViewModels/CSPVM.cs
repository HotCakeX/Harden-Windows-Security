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

using System.Collections.Frozen;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Win32;

namespace HardenSystemSecurity.ViewModels;

internal sealed class CspPolicyEntry(
	string? name,
	string? omaUri,
	string? description,
	string? format,
	string? defaultValue,
	string? accessTypes,
	string? allowedValues,
	string? scope)
{
	[JsonInclude]
	[JsonPropertyOrder(0)]
	internal string? Name => name;

	[JsonInclude]
	[JsonPropertyOrder(1)]
	internal string? OmaUri => omaUri;

	[JsonInclude]
	[JsonPropertyOrder(2)]
	internal string? Description => description;

	[JsonInclude]
	[JsonPropertyOrder(3)]
	internal string? Format => format;

	[JsonInclude]
	[JsonPropertyOrder(4)]
	internal string? DefaultValue => defaultValue;

	[JsonInclude]
	[JsonPropertyOrder(5)]
	internal string? AccessTypes => accessTypes;

	[JsonInclude]
	[JsonPropertyOrder(6)]
	internal string? AllowedValues => allowedValues;

	[JsonInclude]
	[JsonPropertyOrder(7)]
	internal string? Scope => scope;

	[JsonInclude]
	[JsonPropertyOrder(8)]
	internal string? CurrentValue { get; set; }

	[JsonIgnore]
	internal bool HasAppliedValue { get; set; }
}

/// <summary>
/// JSON source generation context for <see cref="CspPolicyEntry"/>
/// </summary>
[JsonSerializable(typeof(CspPolicyEntry))]
[JsonSerializable(typeof(List<CspPolicyEntry>))]
[JsonSourceGenerationOptions(
	WriteIndented = true,
	PropertyNamingPolicy = JsonKnownNamingPolicy.Unspecified,
	PropertyNameCaseInsensitive = true,
	DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
internal sealed partial class CspPolicyEntryJsonContext : JsonSerializerContext
{
}

/// <summary>
/// The source of the DDF data used.
/// For displaying purpose on the UI.
/// </summary>
internal enum DDFDataSource
{
	NotLoaded,
	LocalFiles,
	CachedDownload,
	FreshDownload
}

internal sealed partial class CSPVM : ViewModelBase
{
	/// <summary>
	/// https://learn.microsoft.com/en-us/windows/client-management/mdm/configuration-service-provider-ddf
	/// </summary>
	private static readonly Uri DDFPackageDownloadURL = new("https://download.microsoft.com/download/2ff2c8b9-2e3f-47af-89e6-11c19b7f0c2a/DDFv2Sept25.zip");

	internal InfoBarSettings MainInfoBar { get; }

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); } = true;
	internal Visibility ProgressBarVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;
	internal double ProgressValue { get; set => SP(ref field, value); }
	internal bool IsLoadingIndeterminate { get; set => SP(ref field, value); }

	/// <summary>
	/// Tracks the Toggle Button's state on the UI.
	/// </summary>
	internal bool OnlyShowingAppliedValues
	{
		get; set
		{
			if (SP(ref field, value))
			{
				PerformSearch(SearchKeyword);
			}
		}
	}

	internal bool ElementsAreEnabled
	{
		get; set
		{
			if (SP(ref field, value))
				ProgressBarVisibility = value ? Visibility.Collapsed : Visibility.Visible;
		}
	} = true;

	/// <summary>
	/// Collection bound to the UI ListView.
	/// </summary>
	internal ObservableCollection<CspPolicyEntry> Policies = [];

	/// <summary>
	/// Backing field used for filtering etc.
	/// </summary>
	private List<CspPolicyEntry> AllPolicies = [];

	/// <summary>
	/// Local Files Path Cache.
	/// </summary>
	private readonly List<string> LocalFilePaths = [];

	/// <summary>
	/// In-Memory ZIP Cache so we don't download the DDF file zip again after it's been already downloaded once.
	/// </summary>
	private ReadOnlyMemory<byte>? CachedZipData;

	/// <summary>
	/// To dispaly the source of the DDF data on the UI.
	/// </summary>
	internal DDFDataSource DataSourceName { get; set => SP(ref field, value); } = DDFDataSource.NotLoaded;

	/// <summary>
	/// Search keyword for filtering policies.
	/// </summary>
	internal string? SearchKeyword
	{
		get; set
		{
			if (SPT(ref field, value))
				PerformSearch(value);
		}
	}

	internal CSPVM() => MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

	/// <summary>
	/// Event handler to open file picker to collect XML files.
	/// </summary>
	internal void BrowseForDdfFiles_Click()
	{
		List<string> files = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (files.Count > 0)
		{
			LocalFilePaths.Clear();
			LocalFilePaths.AddRange(files);
			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SelectedLocalFilesReady"), files.Count));
			DataSourceName = DDFDataSource.LocalFiles;
		}
	}

	/// <summary>
	/// Event handler for the UI load button.
	/// </summary>
	internal async void LoadData_Click()
	{
		try
		{
			ElementsAreEnabled = false;

			using IDisposable taskTracker = CommonCore.TaskTracking.RegisterOperation();

			// Clear the collection and backing field.
			Policies.Clear();
			AllPolicies.Clear();

			ProgressValue = 0;
			IsLoadingIndeterminate = true;

			List<CspPolicyEntry> workingEntries = [];

			await Task.Run(async () =>
			{
				// Priorities: Local Files -> Cached ZIP -> Fresh Download

				// Try Local Files first
				if (LocalFilePaths.Count > 0)
				{
					MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("ParsingLocalFiles"), LocalFilePaths.Count));
					workingEntries = CspDdfParser.ParseFiles(LocalFilePaths);

					if (workingEntries.Count > 0)
					{
						DataSourceName = DDFDataSource.LocalFiles;
					}
					else
					{
						MainInfoBar.WriteWarning(GlobalVars.GetStr("LocalFilesNoValidPolicies"));
					}
				}

				// If Local failed or wasn't selected, use Cache/Download
				if (workingEntries.Count == 0)
				{
					if (CachedZipData.HasValue)
					{
						// Use Cache
						MainInfoBar.WriteInfo(GlobalVars.GetStr("UsingCachedDefinitions"));
						workingEntries = CspDdfParser.ParseZipArchive(CachedZipData.Value);
						DataSourceName = DDFDataSource.CachedDownload;
					}
					else
					{
						// Download Fresh
						MainInfoBar.WriteInfo(GlobalVars.GetStr("DownloadingDDFDefinitions"));

						byte[] rawData = await SecHttpClient.Instance.GetByteArrayAsync(DDFPackageDownloadURL);

						// Store in cache
						CachedZipData = new(rawData);

						MainInfoBar.WriteInfo(GlobalVars.GetStr("ProcessingDownloadedDefinitions"));
						workingEntries = CspDdfParser.ParseZipArchive(CachedZipData.Value);
						DataSourceName = DDFDataSource.FreshDownload;
					}
				}

				if (workingEntries.Count == 0)
				{
					MainInfoBar.WriteWarning(GlobalVars.GetStr("NoValidDDFPolicies"));
					DataSourceName = DDFDataSource.NotLoaded;
					ElementsAreEnabled = true;
					return;
				}

				// Query Data
				IsLoadingIndeterminate = false;
				MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("QueryingSystemForPolicies"), workingEntries.Count));

				UpdateValues(workingEntries, (pct) => ProgressValue = pct); // a callback to report progress

				AllPolicies = workingEntries;
			});

			// Add data to the Observable Collection
			foreach (CspPolicyEntry p in CollectionsMarshal.AsSpan(workingEntries))
			{
				Policies.Add(p);
			}

			PerformSearch(SearchKeyword);

			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SuccessfullyLoadedAndQueriedPolicies"), workingEntries.Count));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
			DataSourceName = DDFDataSource.NotLoaded;
		}
		finally
		{
			ElementsAreEnabled = true;
			IsLoadingIndeterminate = false;
			ProgressValue = 0;
		}
	}

	/// <summary>
	/// Event handler for the Clear Button.
	/// </summary>
	internal void ClearData_Click()
	{
		Policies.Clear();
		AllPolicies.Clear();

		// Clear all caches
		LocalFilePaths.Clear();
		CachedZipData = null;

		DataSourceName = DDFDataSource.NotLoaded;
		SearchKeyword = string.Empty;
	}

	/// <summary>
	/// Mappings of ListView tags and their values used for copying etc.
	/// </summary>
	private static readonly FrozenDictionary<string, (string Label, Func<CspPolicyEntry, object?> Getter)> Mappings =
		new Dictionary<string, (string Label, Func<CspPolicyEntry, object?> Getter)>(7, StringComparer.OrdinalIgnoreCase)
		{
			{ "Name", (GlobalVars.GetStr("NameHeader/Text"), static x => x.Name) },
			{ "CurrentValue", (GlobalVars.GetStr("CurrentValueHeader/Text"), static x => x.CurrentValue) },
			{ "DefaultValue", (GlobalVars.GetStr("DefaultValueHeader/Text"), static x => x.DefaultValue) },
			{ "OMAURI", ("OMA-URI", static x => x.OmaUri) },
			{ "Description", (GlobalVars.GetStr("DescriptionHeader/Text"), static x => x.Description) },
			{ "Format", (GlobalVars.GetStr("FormatHeader/Text"), static x => x.Format) },
			{ "Access", (GlobalVars.GetStr("AccessTypeHeader/Text"), static x => x.AccessTypes) }
		}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

	/// <summary>
	/// Event handler for copying the selected row in the ListView.
	/// </summary>
	internal void CopySelected_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.CSPData);
		if (lv is null) return;
		if (lv.SelectedItems.Count > 0)
		{
			// SelectedItems is an IList
			ListViewHelper.ConvertRowToText(lv.SelectedItems, Mappings);
		}
	}

	/// <summary>
	/// Event handler for the copy button of OMA-URI.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void CopyOmaUri_Click(object sender, RoutedEventArgs e)
	{
		if (sender is FrameworkElement { DataContext: CspPolicyEntry entry } && !string.IsNullOrEmpty(entry.OmaUri))
		{
			ClipboardManagement.CopyText(entry.OmaUri);
		}
	}

	/// <summary>
	/// Updates the CurrentValue property of each entry in the specified collection by querying the corresponding OMA URI.
	/// </summary>
	/// <param name="entries">The policies to query.</param>
	/// <param name="reportProgress">Callback to report progress (0-100).</param>
	private static void UpdateValues(List<CspPolicyEntry> entries, Action<double> reportProgress)
	{
		LocalMdmClient client = new();
		int total = entries.Count;
		int current = 0;

		// Capture existing state before modifying
		EmbeddedModeUtil.EmbeddedFlagsSnapshot snapshot = EmbeddedModeUtil.ReadEmbeddedModeFlagsSnapshot();
		EmbeddedModeUtil.SetEmbeddedModeFlag();

		try
		{
			foreach (CspPolicyEntry entry in CollectionsMarshal.AsSpan(entries))
			{
				// Only query if "Get" is allowed and URI is present
				if (!string.IsNullOrEmpty(entry.AccessTypes) &&
					entry.AccessTypes.Contains("Get", StringComparison.OrdinalIgnoreCase) &&
					!string.IsNullOrEmpty(entry.OmaUri))
				{
					(string val, bool success) = client.QueryValue(entry.OmaUri);
					entry.CurrentValue = val;
					entry.HasAppliedValue = success;
				}
				else
				{
					entry.CurrentValue = null;
					entry.HasAppliedValue = false;
				}

				current++;

				// Update progress every 20 items to reduce UI marshalling overhead
				if (current % 20 == 0 || current == total)
				{
					double pct = (double)current / total * 100.0;
					reportProgress(pct);
				}
			}
		}
		finally
		{
			// Unregister device and check result
			uint result = NativeMethods.UnregisterDeviceWithLocalManagement();
			if (result != 0)
			{
				Logger.Write(string.Format(GlobalVars.GetStr("FailedToUnregisterDevice"), result));
			}

			// Restore original registry state
			EmbeddedModeUtil.RestoreEmbeddedModeFlag(snapshot);
		}
	}

	/// <summary>
	/// Filters the <see cref="AllPolicies"/> list based on the <see cref="SearchKeyword"/>
	/// and populates the <see cref="Policies"/> with the results.
	/// </summary>
	/// <param name="searchKeyword">The term to search for.</param>
	private void PerformSearch(string? searchKeyword)
	{
		string? term = searchKeyword?.Trim();

		// If there is no search term and no filter applied, just show all (if not already showing all)
		if (string.IsNullOrEmpty(term) && !OnlyShowingAppliedValues)
		{
			if (Policies.Count != AllPolicies.Count)
			{
				Policies.Clear();
				foreach (CspPolicyEntry p in CollectionsMarshal.AsSpan(AllPolicies))
				{
					Policies.Add(p);
				}
			}
			return;
		}

		IEnumerable<CspPolicyEntry> query = AllPolicies;

		// Filter by Applied Status
		if (OnlyShowingAppliedValues)
			query = query.Where(p => p.HasAppliedValue);

		// Filter by Search Keyword
		if (!string.IsNullOrEmpty(term))
		{
			query = query.Where(p =>
				(p.Name?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.OmaUri?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.Description?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.CurrentValue?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.DefaultValue?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.Format?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.AccessTypes?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.AllowedValues?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.Scope?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false)
			);
		}

		List<CspPolicyEntry> filtered = query.ToList();

		Policies.Clear();
		foreach (CspPolicyEntry p in CollectionsMarshal.AsSpan(filtered))
		{
			Policies.Add(p);
		}
	}

	internal static class EmbeddedModeUtil
	{
		private static byte[]? _cachedHash;

		internal struct EmbeddedFlagsSnapshot
		{
			internal bool Exists;
			internal RegistryValueKind Kind;
			internal object? Data;
		}

		private static byte[] GetComputedHash()
		{
			if (_cachedHash is not null)
				return _cachedHash;

			string uuid = QuantumRelayHSS.Client.RunCommand(GlobalVars.ComManagerProcessPath, "get root\\cimv2 Win32_ComputerSystemProduct UUID");
			uuid = uuid.Trim('"');

			Guid g = Guid.Parse(uuid);
			byte[] bytes = g.ToByteArray();
			_cachedHash = System.Security.Cryptography.SHA256.HashData(bytes);

			return _cachedHash;
		}

		internal static EmbeddedFlagsSnapshot ReadEmbeddedModeFlagsSnapshot()
		{
			EmbeddedFlagsSnapshot snap = new()
			{
				Exists = false,
				Kind = RegistryValueKind.None,
				Data = null
			};
			try
			{
				using RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\embeddedmode\Parameters", writable: false);
				if (key != null)
				{
					object? data = key.GetValue("Flags");
					if (data is not null)
					{
						snap.Exists = true;
						snap.Data = data;
						snap.Kind = key.GetValueKind("Flags");
					}
				}
			}
			catch (Exception ex)
			{
				// Ignore exceptions during snapshot read, defaulting to non-existent
				Logger.Write(ex);
			}
			return snap;
		}

		/// <summary>
		/// The module Embeddedmodesvcapi.dll has a function named "GetFlags()", responsible for verifying the flag.
		/// </summary>
		/// <exception cref="InvalidOperationException"></exception>
		internal static void SetEmbeddedModeFlag()
		{
			using RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\embeddedmode\Parameters", writable: true)
				?? throw new InvalidOperationException("Failed to open embeddedmode Parameters key.");

			key.SetValue("Flags", GetComputedHash(), RegistryValueKind.Binary);
		}

		internal static void RestoreEmbeddedModeFlag(EmbeddedFlagsSnapshot snapshot)
		{
			try
			{
				using RegistryKey? key = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\embeddedmode\Parameters", writable: true);
				if (key == null) return;

				if (snapshot.Exists && snapshot.Data is not null)
				{
					key.SetValue("Flags", snapshot.Data, snapshot.Kind);
				}
				else
				{
					// If it didn't exist before, or read failed (data is null), ensure it's gone.
					key.DeleteValue("Flags", throwOnMissingValue: false);
				}
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}
		}
	}

	private static class CspDdfParser
	{
		internal static List<CspPolicyEntry> ParseFiles(IEnumerable<string> filePaths)
		{
			List<CspPolicyEntry> results = [];
			foreach (string file in filePaths)
			{
				if (!File.Exists(file)) continue;
				try
				{
					XDocument doc = XDocument.Load(file);
					ParseNode(doc.Root, string.Empty, false, results);
				}
				catch (Exception ex)
				{
					Logger.Write(string.Format(GlobalVars.GetStr("FailedToParseFile"), file));
					Logger.Write(ex);
				}
			}
			return results;
		}

		internal static List<CspPolicyEntry> ParseZipArchive(ReadOnlyMemory<byte> zipData)
		{
			List<CspPolicyEntry> results = [];

			using MemoryStream ms = new(zipData.ToArray());

			using ZipArchive archive = new(ms, ZipArchiveMode.Read);

			foreach (ZipArchiveEntry entry in archive.Entries)
			{
				if (entry.FullName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
				{
					try
					{
						using Stream entryStream = entry.Open();
						XDocument doc = XDocument.Load(entryStream);
						ParseNode(doc.Root, string.Empty, false, results);
					}
					catch (Exception ex)
					{
						Logger.Write(string.Format(GlobalVars.GetStr("FailedToParseZipEntry"), entry.FullName));
						Logger.Write(ex);
					}
				}
			}
			return results;
		}

		private static void ParseNode(XElement? element, string parentPath, bool hasDynamicAncestor, List<CspPolicyEntry> collector)
		{
			if (element is null)
				return;

			foreach (XElement node in element.Elements())
			{
				if (!node.Name.LocalName.Equals("Node", StringComparison.OrdinalIgnoreCase))
					continue;

				string nodeName = node.Element("NodeName")?.Value ?? string.Empty;
				string? explicitPath = node.Element("Path")?.Value;

				string basePath = parentPath;
				if (!string.IsNullOrWhiteSpace(explicitPath))
				{
					basePath = NormalizeBasePath(explicitPath);
				}

				string currentPath = basePath;
				bool isThisDynamic = string.IsNullOrWhiteSpace(nodeName);

				if (!isThisDynamic)
				{
					currentPath = CombinePath(basePath, nodeName);
				}

				XElement? props = node.Element("DFProperties");
				if (props != null)
				{
					XElement? format = props.Element("DFFormat");
					bool isLeaf = format != null && !format.Elements().Any(e => e.Name.LocalName.Equals("node", StringComparison.OrdinalIgnoreCase));

					if (isLeaf)
					{
						bool hasGet = props.Element("AccessType")?.Elements().Any(a => a.Name.LocalName.Equals("Get", StringComparison.OrdinalIgnoreCase)) == true;

						bool requiresInstance = hasDynamicAncestor || isThisDynamic;

						if (hasGet && !requiresInstance)
						{
							collector.Add(new CspPolicyEntry(
								nodeName,
								EnsureDotSlash(currentPath),
								props.Element("Description")?.Value?.Trim(),
								format?.Elements().FirstOrDefault()?.Name.LocalName.Trim() ?? GlobalVars.GetStr("UnknownState"),
								props.Element("DefaultValue")?.Value,
								string.Join(", ", props.Element("AccessType")?.Elements().Select(e => e.Name.LocalName) ?? []),
								GetAllowedValues(props),
								props.Element("Scope")?.Elements().FirstOrDefault()?.Name.LocalName
							));
						}
					}
				}

				ParseNode(node, currentPath, hasDynamicAncestor || isThisDynamic, collector);
			}
		}

		private static string GetAllowedValues(XElement props)
		{
			// Retrieve the AllowedValues element
			XElement? allowed = props.Elements().FirstOrDefault(e => e.Name.LocalName.Equals("AllowedValues", StringComparison.OrdinalIgnoreCase));
			if (allowed is null) return string.Empty;

			// Determine the ValueType. Default to ENUM if not present.
			string valType = allowed.Attributes().FirstOrDefault(a => a.Name.LocalName.Equals("ValueType", StringComparison.OrdinalIgnoreCase))?.Value ?? "ENUM";

			if (valType.Equals("ENUM", StringComparison.OrdinalIgnoreCase))
			{
				List<XElement> enums = allowed.Elements().Where(e => e.Name.LocalName.Equals("Enum", StringComparison.OrdinalIgnoreCase)).ToList();
				if (enums.Count > 0)
				{
					StringBuilder sb = new();
					foreach (XElement en in CollectionsMarshal.AsSpan(enums))
					{
						string val = en.Elements().FirstOrDefault(x => x.Name.LocalName.Equals("Value", StringComparison.OrdinalIgnoreCase))?.Value ?? "";
						string desc = en.Elements().FirstOrDefault(x => x.Name.LocalName.Equals("ValueDescription", StringComparison.OrdinalIgnoreCase))?.Value ?? "";
						if (sb.Length > 0) _ = sb.Append("; ");
						_ = sb.Append($"{val} ({desc})");
					}
					return sb.ToString();
				}
			}
			else if (valType.Equals("Range", StringComparison.OrdinalIgnoreCase))
			{
				// e.g.,: <MSFT:Value>[0-10000]</MSFT:Value>
				return allowed.Elements().FirstOrDefault(e => e.Name.LocalName.Equals("Value", StringComparison.OrdinalIgnoreCase))?.Value ?? string.Empty;
			}
			else if (valType.Equals("ADMX", StringComparison.OrdinalIgnoreCase))
			{
				// e.g.,: <MSFT:AdmxBacked Area="..." Name="..." File="..." />
				XElement? admx = allowed.Elements().FirstOrDefault(e => e.Name.LocalName.Equals("AdmxBacked", StringComparison.OrdinalIgnoreCase));
				if (admx is not null)
				{
					string file = admx.Attributes().FirstOrDefault(a => a.Name.LocalName.Equals("File", StringComparison.OrdinalIgnoreCase))?.Value ?? "";
					string name = admx.Attributes().FirstOrDefault(a => a.Name.LocalName.Equals("Name", StringComparison.OrdinalIgnoreCase))?.Value ?? "";
					// Constructing a representation string
					return string.Format(GlobalVars.GetStr("AdmxFilePolicyFormat"), file, name);
				}
			}
			else if (valType.Equals("XSD", StringComparison.OrdinalIgnoreCase))
			{
				// e.g.,: <MSFT:Value><![CDATA[<xs:schema ...]]></MSFT:Value>
				return allowed.Elements().FirstOrDefault(e => e.Name.LocalName.Equals("Value", StringComparison.OrdinalIgnoreCase))?.Value ?? GlobalVars.GetStr("XSDSchemaText");
			}

			return string.Empty;
		}

		private static string NormalizeBasePath(string path)
		{
			string p = (path ?? string.Empty).Trim();
			p = p.Replace('\\', '/');

			while (p.Contains("//", StringComparison.Ordinal))
			{
				p = p.Replace("//", "/", StringComparison.Ordinal);
			}

			if (p.EndsWith('/') && !p.Equals("./", StringComparison.Ordinal))
			{
				p = p.TrimEnd('/');
			}

			if (p.Equals(".", StringComparison.Ordinal))
			{
				p = "./";
			}

			p = EnsureDotSlash(p);

			return p;
		}

		private static string CombinePath(string basePath, string segment)
		{
			string b = string.IsNullOrWhiteSpace(basePath) ? "./" : EnsureDotSlash(basePath);
			string s = (segment ?? string.Empty).Trim();

			if (s.Length == 0) return b;

			if (!b.EndsWith('/'))
			{
				b += "/";
			}
			string combined = b + s;

			while (combined.Contains("//", StringComparison.Ordinal))
			{
				combined = combined.Replace("//", "/", StringComparison.Ordinal);
			}
			return combined;
		}

		private static string EnsureDotSlash(string path)
		{
			if (string.IsNullOrWhiteSpace(path)) return "./";
			string p = path.Trim();

			if (p.StartsWith("./", StringComparison.Ordinal)) return p;
			if (p.StartsWith('.')) return "./" + p.AsSpan(1).ToString();
			if (p.StartsWith('/')) return "." + p;

			return "./" + p;
		}
	}

	private sealed class LocalMdmClient
	{
		private uint _cmdCounter;

		private readonly StringBuilder _sb = new(500);

		internal (string Value, bool Success) QueryValue(string omaUri)
		{
			try
			{
				uint hr = NativeMethods.RegisterDeviceWithLocalManagement(out _);
				if (hr != 0) return (string.Format(GlobalVars.GetStr("RegisterFailedFormat"), hr), false);

				// Increment first, then build using the new ID.
				_cmdCounter++;
				string syncBody = BuildGetBody(omaUri, _cmdCounter);

				string resultXml = Apply(syncBody);

				int status = ParseStatusCode(resultXml);

				if (status == 200)
				{
					string val = ExtractResultData(resultXml);
					string finalVal = string.IsNullOrEmpty(val) ? GlobalVars.GetStr("EmptyText") : val.Trim();
					return (finalVal, true);
				}
				else if (status == 404)
				{
					return (GlobalVars.GetStr("NotFoundText"), false);
				}
				else
				{
					return (string.Format(GlobalVars.GetStr("StatusFormat"), status), false);
				}
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				return ($"(Ex: {ex.Message})", false);
			}
		}

		private string BuildGetBody(string omaUri, uint cmdId)
		{
			_ = _sb.Clear();
			_ = _sb.Append("<SyncBody>\n");
			_ = _sb.Append("<Get>\n");
			_ = _sb.Append("  <CmdID>").Append(cmdId).Append("</CmdID>\n");
			_ = _sb.Append("  <Item>\n");
			_ = _sb.Append("    <Target>\n");
			_ = _sb.Append("      <LocURI>").Append(EscapeXml(omaUri)).Append("</LocURI>\n");
			_ = _sb.Append("    </Target>\n");
			_ = _sb.Append("  </Item>\n");
			_ = _sb.Append("</Get>\n");
			_ = _sb.Append("</SyncBody>");
			return _sb.ToString();
		}

		private static string Apply(string syncML)
		{
			uint rc = NativeMethods.ApplyLocalManagementSyncML(syncML, out IntPtr resultPtr);
			string resultXml = string.Empty;

			if (resultPtr != IntPtr.Zero)
			{
				try
				{
					resultXml = Marshal.PtrToStringUni(resultPtr) ?? string.Empty;
				}
				finally
				{
					IntPtr freeResult = NativeMethods.LocalFree(resultPtr);
					if (freeResult != IntPtr.Zero)
					{
						Logger.Write($"Failed to free memory allocated for LocalFree.");
					}
				}
			}

			if (rc == 2147549446U) throw new InvalidOperationException("MDM local management needs MTA T Model.");
			if (resultXml.StartsWith("Error", StringComparison.Ordinal)) throw new InvalidOperationException(resultXml);
			if (rc != 0U) throw new Win32Exception(unchecked((int)rc), "Unexpected return code: " + rc.ToString());

			return resultXml;
		}

		private static string EscapeXml(string value) =>
			 System.Security.SecurityElement.Escape(value) ?? string.Empty;

		private static int ParseStatusCode(string resultXml)
		{
			if (string.IsNullOrEmpty(resultXml)) return -1;
			try
			{
				XmlDocument doc = new();
				doc.LoadXml(resultXml);
				XmlNodeList statusNodes = doc.GetElementsByTagName("Status");
				if (statusNodes != null && statusNodes.Count > 1)
				{
					XmlNode statusNode = statusNodes[1]!;
					foreach (XmlNode child in statusNode.ChildNodes)
					{
						if (child.NodeType is XmlNodeType.Element && child.Name.Equals("Data", StringComparison.Ordinal))
						{
							string txt = child.InnerText.Trim();
							if (int.TryParse(txt, out int code)) return code;
						}
					}
				}
			}
			catch { }
			return -1;
		}

		private static string ExtractResultData(string resultXml)
		{
			if (string.IsNullOrEmpty(resultXml)) return string.Empty;
			try
			{
				XmlDocument doc = new();
				doc.LoadXml(resultXml);
				XmlNodeList resultsNodes = doc.GetElementsByTagName("Results");
				if (resultsNodes != null && resultsNodes.Count > 0)
				{
					XmlNode resultsNode = resultsNodes[0]!;
					foreach (XmlNode itemChild in resultsNode.ChildNodes)
					{
						if (itemChild.NodeType is XmlNodeType.Element && itemChild.Name.Equals("Item", StringComparison.Ordinal))
						{
							foreach (XmlNode ic in itemChild.ChildNodes)
							{
								if (ic.NodeType is XmlNodeType.Element && ic.Name.Equals("Data", StringComparison.Ordinal))
								{
									return ic.InnerText;
								}
							}
						}
					}
				}
			}
			catch { }
			return string.Empty;
		}
	}

	#region Export

	/// <summary>
	/// Exports the current CSP Data to a JSON file
	/// </summary>
	internal async void ExportToJson_Click()
	{
		try
		{
			if (Policies.Count == 0)
				return;

			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			string? saveLocation = FileDialogHelper.ShowSaveFileDialog(
					"CSP Effective Results|*.JSON",
					"CSP Effective Results.JSON");

			if (saveLocation is null)
				return;

			List<CspPolicyEntry> CSPData = Policies.ToList();

			await Task.Run(() =>
			{
				string jsonString = JsonSerializer.Serialize(CSPData, CspPolicyEntryJsonContext.Default.ListCspPolicyEntry);

				File.WriteAllText(saveLocation, jsonString, Encoding.UTF8);
			});

			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SuccessfullyExportedCSPData"), CSPData.Count, saveLocation));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	#endregion
}
