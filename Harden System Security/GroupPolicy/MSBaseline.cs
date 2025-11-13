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
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.CustomUIElements;
using HardenSystemSecurity.SecurityPolicy;

#pragma warning disable CA1819

namespace HardenSystemSecurity.GroupPolicy;

/// <summary>
/// Enum representing the source type of a security measure
/// </summary>
internal enum SecurityMeasureSource : uint
{
	AuditPolicy = 0,
	GroupPolicy = 1,
	SystemAccess = 2,
	Privilege = 3,
	SecurityPolicyRegistry = 4
}

[JsonSourceGenerationOptions(
	PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
	PropertyNameCaseInsensitive = true,
	WriteIndented = true)]
[JsonSerializable(typeof(VerificationResult))]
[JsonSerializable(typeof(List<VerificationResult>))]
internal sealed partial class VerificationResultJsonContext : JsonSerializerContext
{
}

/// <summary>
/// Represents the verification result for a single security measure.
/// </summary>
internal sealed class VerificationResult(
	string friendlyName,
	SecurityMeasureSource source,
	bool isCompliant,
	string currentValue,
	string expectedValue)
{
	[JsonInclude]
	[JsonPropertyOrder(0)]
	[JsonPropertyName("Friendly Name")]
	internal string FriendlyName => friendlyName;

	[JsonIgnore]
	internal SecurityMeasureSource Source => source;

	[JsonInclude]
	[JsonPropertyOrder(1)]
	[JsonPropertyName("Is Compliant")]
	internal bool IsCompliant => isCompliant;

	[JsonInclude]
	[JsonPropertyOrder(2)]
	[JsonPropertyName("Current Value")]
	internal string CurrentValue => currentValue;

	[JsonInclude]
	[JsonPropertyOrder(3)]
	[JsonPropertyName("Expected Value")]
	internal string ExpectedValue => expectedValue;

	/// <summary>
	/// Property for StatusIndicator binding
	/// </summary>
	[JsonIgnore]
	internal StatusState ComplianceStatus => IsCompliant ? StatusState.Applied : StatusState.NotApplied;

	/// <summary>
	/// Property for source display
	/// </summary>
	[JsonInclude]
	[JsonPropertyOrder(4)]
	[JsonPropertyName("Source")]
	internal string SourceDisplay => Source switch
	{
		SecurityMeasureSource.AuditPolicy => "Audit Policy",
		SecurityMeasureSource.GroupPolicy => "Group Policy",
		SecurityMeasureSource.SystemAccess => "System Access",
		SecurityMeasureSource.Privilege => "Privilege",
		SecurityMeasureSource.SecurityPolicyRegistry => "Security Policy Registry",
		_ => "Unknown"
	};

	/// <summary>
	/// Saves a list of VerificationResult to a JSON file.
	/// </summary>
	/// <param name="path">The file path to save to</param>
	/// <param name="results">The verification results to save</param>
	internal static void Save(string path, List<VerificationResult> results)
	{
		string json = JsonSerializer.Serialize(results, VerificationResultJsonContext.Default.ListVerificationResult);
		File.WriteAllText(path, json);
	}
}

/// <summary>
/// This class contains all of the logic for processing Microsoft Security Baselines such as
/// Microsoft Security Baselines and Microsoft 365 Apps Security Baselines.
/// </summary>
internal static class MSBaseline
{
	internal enum Action
	{
		Apply,
		Verify,
		Remove
	}

	/// <summary>
	/// Represents a cached download entry with expiration tracking.
	/// Stores compressed data to minimize memory usage.
	/// </summary>
	private sealed class CacheEntry(
		byte[] compressedData,
		DateTime cachedAt,
		int originalSize
		)
	{
		internal byte[] CompressedData => compressedData;
		internal DateTime CachedAt => cachedAt;
		internal int OriginalSize => originalSize;
		internal bool IsExpired => DateTime.UtcNow - CachedAt > TimeSpan.FromHours(2);
	}

	/// <summary>
	/// Cache for downloaded ZIP files.
	/// </summary>
	private static readonly ConcurrentDictionary<Uri, CacheEntry> _downloadCache = new();

	/// <summary>
	/// Compresses data using Brotli compression.
	/// </summary>
	/// <param name="data">Raw data to compress</param>
	/// <returns>Compressed data</returns>
	private static byte[] CompressData(byte[] data)
	{
		using MemoryStream output = new();
		using (BrotliStream compressionStream = new(output, CompressionLevel.Optimal))
		{
			compressionStream.Write(data, 0, data.Length);
		}
		return output.ToArray();
	}

	/// <summary>
	/// Decompresses Brotli-compressed data.
	/// </summary>
	/// <param name="compressedData">Compressed data to decompress</param>
	/// <returns>Original uncompressed data</returns>
	private static byte[] DecompressData(byte[] compressedData)
	{
		using MemoryStream input = new(compressedData);
		using BrotliStream decompressionStream = new(input, CompressionMode.Decompress);
		using MemoryStream output = new();
		decompressionStream.CopyTo(output);
		return output.ToArray();
	}

	/// <summary>
	/// Holds Security Policies data that are parsed from one or more INF files exported by the Secedit.
	/// </summary>
	private sealed class ParsedInfData(
		Dictionary<string, string[]> privilegeRights,
		List<RegistryPolicyEntry> registryPolicyEntries
		)
	{
		internal Dictionary<string, string[]> PrivilegeRights => privilegeRights;
		internal List<RegistryPolicyEntry> RegistryPolicyEntries => registryPolicyEntries;
	}

	/// <summary>
	/// Represents an in-memory file with its path and content.
	/// </summary>
	private sealed class InMemoryFile(string relativePath, byte[] content)
	{
		internal string RelativePath => relativePath;
		internal byte[] Content => content;
	}

	/// <summary>
	/// Downloads, processes and applies, removes, or verifies Microsoft Baseline from the specified URL without saving any temporary files to disk.
	/// </summary>
	/// <param name="downloadUrl">URL to download the security baseline ZIP file</param>
	/// <param name="action">Whether to apply, remove, or verify the baseline policies</param>
	/// <returns>List of VerificationResult if action is Verify, null otherwise</returns>
	/// <exception cref="InvalidOperationException">Thrown when download or operation fails</exception>
	internal static async Task<List<VerificationResult>?> DownloadAndProcessSecurityBaseline(
		Uri downloadUrl,
		Action action,
		CancellationToken? cancellationToken = null)
	{
		// Many methods simply don't run in Async mode so we make sure the entire thing runs in another thread to prevent UI blocks
		return await Task.Run(async () =>
		{
			string actionText = action switch
			{
				Action.Apply => "application",
				Action.Remove => "removal",
				Action.Verify => "verification",
				_ => throw new InvalidOperationException("Invalid action specified")
			};

			// Log depending on source type
			string startVerb = downloadUrl.IsFile ? "load" : "download";
			Logger.Write($"Starting {startVerb} and {actionText} of the Baseline from: {downloadUrl}");

			cancellationToken?.ThrowIfCancellationRequested();

			// Obtain ZIP bytes either from local file or over HTTP
			byte[] zipContent = downloadUrl.IsFile
				? await ReadBaselineZipFromFileAsync(downloadUrl)
				: await DownloadSecurityBaselineZip(downloadUrl);

			Logger.Write($"Obtained ZIP file into memory ({zipContent.Length:N0} bytes)");

			cancellationToken?.ThrowIfCancellationRequested();

			// Extract the ZIP file into memory
			List<InMemoryFile> extractedFiles = ExtractSecurityBaselineZip(zipContent);
			Logger.Write($"Extracted {extractedFiles.Count} files into memory");

			cancellationToken?.ThrowIfCancellationRequested();

			// Find the baseline root directory
			string baselineRootPath = FindSecurityBaselineRoot(extractedFiles);
			Logger.Write($"Found security baseline root: {baselineRootPath}");

			cancellationToken?.ThrowIfCancellationRequested();

			// Copy policy definition templates (always done regardless of action)
			CopyPolicyDefinitionTemplates(extractedFiles, baselineRootPath);

			cancellationToken?.ThrowIfCancellationRequested();

			// Handle different actions
			if (action == Action.Verify)
			{
				List<VerificationResult> results = await VerifySecurityBaselinePolicies(extractedFiles, baselineRootPath, cancellationToken);
				Logger.Write($"{baselineRootPath} {actionText} completed successfully");

				return results;
			}
			else
			{
				// Find and apply/remove policies based on action
				PolicyAction policyAction = action == Action.Apply ? PolicyAction.Apply : PolicyAction.Remove;
				ApplyOrRemoveSecurityBaselinePolicies(extractedFiles, baselineRootPath, policyAction, cancellationToken);
				Logger.Write($"{baselineRootPath} {actionText} completed successfully");
				return null;
			}
		}, cancellationToken ?? default);
	}

	/// <summary>
	/// Reads baseline ZIP from a local file path when a file:// URI is provided
	/// </summary>
	private static async Task<byte[]> ReadBaselineZipFromFileAsync(Uri fileUri)
	{
		if (!fileUri.IsFile)
			throw new InvalidOperationException("The provided URI is not a file URI.");

		string path = fileUri.LocalPath;

		if (!File.Exists(path))
			throw new FileNotFoundException($"Baseline ZIP file not found on disk: {path}", path);

		Logger.Write($"Reading security baseline ZIP file from disk: {path}");
		byte[] content = await File.ReadAllBytesAsync(path);
		Logger.Write($"Successfully read {content.Length / 1024.0:N2} KB from disk into memory");
		return content;
	}

	/// <summary>
	/// Downloads the security baseline ZIP file from the specified URL into memory.
	/// Uses caching with 2-hours expiration and Brotli compression to minimize memory usage.
	/// </summary>
	/// <param name="downloadUrl">URL to download from</param>
	/// <returns>ZIP file content as byte array</returns>
	private static async Task<byte[]> DownloadSecurityBaselineZip(Uri downloadUrl)
	{
		// Check cache first - remove expired entry if found
		if (_downloadCache.TryGetValue(downloadUrl, out CacheEntry? cacheEntry))
		{
			if (!cacheEntry.IsExpired)
			{
				Logger.Write($"Using cached ZIP file for {downloadUrl} (compressed: {cacheEntry.CompressedData.Length / 1024.0:N2} KB, original: {cacheEntry.OriginalSize / 1024.0:N2} KB)");
				return DecompressData(cacheEntry.CompressedData);
			}
			else
			{
				// Remove expired entry
				_ = _downloadCache.TryRemove(downloadUrl, out _);
				Logger.Write($"Cached ZIP file for {downloadUrl} has expired, downloading fresh copy");
			}
		}

		using HttpClient httpClient = new();
		httpClient.Timeout = TimeSpan.FromMinutes(5); // 5 minutes timeout to work even with the slowest networks.

		Logger.Write("Starting download of security baseline ZIP file into memory...");

		HttpResponseMessage response = await httpClient.GetAsync(downloadUrl);
		_ = response.EnsureSuccessStatusCode();

		byte[] content = await response.Content.ReadAsByteArrayAsync();
		Logger.Write($"Successfully downloaded {content.Length / 1024.0:N2} KB into memory");

		// Compress and cache the downloaded content
		byte[] compressedData = CompressData(content);
		double compressionRatio = (1.0 - (double)compressedData.Length / content.Length) * 100;
		Logger.Write($"Compressed ZIP file from {content.Length / 1024.0:N2} KB to {compressedData.Length / 1024.0:N2} KB ({compressionRatio:F1}% reduction)");

		_downloadCache[downloadUrl] = new(compressedData: compressedData, cachedAt: DateTime.UtcNow, originalSize: content.Length);

		return content;
	}

	/// <summary>
	/// Extracts the security baseline ZIP file from memory.
	/// </summary>
	/// <param name="zipContent">ZIP file content as byte array</param>
	/// <returns>List of extracted files in memory</returns>
	private static List<InMemoryFile> ExtractSecurityBaselineZip(byte[] zipContent)
	{
		List<InMemoryFile> extractedFiles = [];

		using MemoryStream zipStream = new(zipContent);
		using ZipArchive archive = new(zipStream, ZipArchiveMode.Read);

		foreach (ZipArchiveEntry entry in archive.Entries)
		{
			// Skip directories
			if (string.IsNullOrEmpty(entry.Name))
				continue;

			using Stream entryStream = entry.Open();
			using MemoryStream contentStream = new();
			entryStream.CopyTo(contentStream);

			extractedFiles.Add(new InMemoryFile(entry.FullName, contentStream.ToArray()));
		}

		Logger.Write($"Extracted {extractedFiles.Count} files from ZIP archive");
		return extractedFiles;
	}

	/// <summary>
	/// Finds the security baseline root directory from extracted files by finding the common root of all directories.
	/// </summary>
	/// <param name="extractedFiles">List of extracted files</param>
	/// <returns>Relative path to the security baseline root directory</returns>
	private static string FindSecurityBaselineRoot(List<InMemoryFile> extractedFiles)
	{
		// Get all unique directory paths
		string[] directories = extractedFiles
			.Select(file => Path.GetDirectoryName(file.RelativePath) ?? string.Empty)
			.Where(dir => !string.IsNullOrEmpty(dir))
			.Distinct(StringComparer.OrdinalIgnoreCase)
			.ToArray();

		if (directories.Length == 0)
		{
			throw new InvalidOperationException("No directories found in extracted files");
		}

		// Starting with the first directory and find the common root with all others
		string commonRoot = directories[0];

		for (int i = 1; i < directories.Length; i++)
		{
			commonRoot = GetCommonDirectoryPrefix(commonRoot, directories[i]);
			if (string.IsNullOrEmpty(commonRoot))
			{
				throw new InvalidOperationException("No common root directory found");
			}
		}

		Logger.Write($"Found security baseline root directory: {commonRoot}");
		return commonRoot;
	}

	/// <summary>
	/// Finds the common directory prefix between two paths.
	/// </summary>
	/// <param name="path1">First directory path</param>
	/// <param name="path2">Second directory path</param>
	/// <returns>Common directory prefix</returns>
	private static string GetCommonDirectoryPrefix(string path1, string path2)
	{
		string[] segments1 = path1.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
		string[] segments2 = path2.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

		int commonCount = 0;
		int minLength = Math.Min(segments1.Length, segments2.Length);

		for (int i = 0; i < minLength; i++)
		{
			if (string.Equals(segments1[i], segments2[i], StringComparison.OrdinalIgnoreCase))
			{
				commonCount++;
			}
			else
			{
				break;
			}
		}

		return commonCount > 0
			? string.Join(Path.DirectorySeparatorChar.ToString(), segments1.Take(commonCount))
			: string.Empty;
	}

	/// <summary>
	/// The path to the location on the system where policy templates (ADMX/ADML files) exist.
	/// </summary>
	private static readonly string PolicyDefinitionsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "PolicyDefinitions");

	/// <summary>
	/// Copies policy definition templates to <see cref="PolicyDefinitionsPath"> from memory.
	/// </summary>
	/// <param name="extractedFiles">List of extracted files</param>
	/// <param name="baselineRootPath">Root path of the security baseline</param>
	private static void CopyPolicyDefinitionTemplates(List<InMemoryFile> extractedFiles, string baselineRootPath)
	{
		// Find Templates directory files
		string templatesPrefix = Path.Combine(baselineRootPath, "Templates").Replace('\\', '/');
		if (!templatesPrefix.EndsWith('/'))
			templatesPrefix += '/';

		List<InMemoryFile> templateFiles = extractedFiles
			.Where(file => file.RelativePath.Replace('\\', '/').StartsWith(templatesPrefix, StringComparison.OrdinalIgnoreCase))
			.ToList();

		if (templateFiles.Count == 0)
		{
			Logger.Write("No template files found, skipping policy definition copy");
			return;
		}

		Logger.Write($"Copying {templateFiles.Count} policy definition templates to {PolicyDefinitionsPath}");

		// Ensure destination directory exists
		_ = Directory.CreateDirectory(PolicyDefinitionsPath);

		foreach (InMemoryFile templateFile in templateFiles)
		{
			// Calculate relative path within Templates directory
			string normalizedFilePath = templateFile.RelativePath.Replace('\\', '/');
			string relativePath = normalizedFilePath[templatesPrefix.Length..];

			string destinationPath = Path.Combine(PolicyDefinitionsPath, relativePath.Replace('/', Path.DirectorySeparatorChar));

			// Ensure destination directory exists
			string? destinationDir = Path.GetDirectoryName(destinationPath);
			if (!string.IsNullOrEmpty(destinationDir))
			{
				_ = Directory.CreateDirectory(destinationDir);
			}

			// Write file to disk (overwrite if exists)
			File.WriteAllBytes(destinationPath, templateFile.Content);
			Logger.Write($"Copied template file: {relativePath}");
		}

		Logger.Write("Policy definition templates copied successfully");
	}

	private static HashSet<string> FindAllGUIDDirectoryPaths(List<InMemoryFile> items, string baselineRootPath)
	{
		// Find GPOs directory path
		string gposPrefix = Path.Combine(baselineRootPath, "GPOs").Replace('\\', '/');
		if (!gposPrefix.EndsWith('/'))
			gposPrefix += '/';

		// Find all GUID directory paths
		HashSet<string> guidDirectories = [];
		foreach (InMemoryFile file in items)
		{
			string normalizedPath = file.RelativePath.Replace('\\', '/');
			if (normalizedPath.StartsWith(gposPrefix, StringComparison.OrdinalIgnoreCase))
			{
				string remainingPath = normalizedPath[gposPrefix.Length..];
				string[] pathParts = remainingPath.Split('/');
				if (pathParts.Length > 0 && IsGuidDirectory(pathParts[0]))
				{
					_ = guidDirectories.Add(Path.Combine(gposPrefix.TrimEnd('/'), pathParts[0]).Replace('/', Path.DirectorySeparatorChar));
				}
			}
		}

		Logger.Write($"Found {guidDirectories.Count} GUID directories.");

		return guidDirectories;
	}

	/// <summary>
	/// Verifies all security baseline policies from memory with parallel processing.
	/// </summary>
	/// <param name="extractedFiles">List of extracted files</param>
	/// <param name="baselineRootPath">Root path of the security baseline</param>
	/// <returns>List of verification results</returns>
	private static async Task<List<VerificationResult>> VerifySecurityBaselinePolicies(List<InMemoryFile> extractedFiles, string baselineRootPath, CancellationToken? cancellationToken = null)
	{
		// Find all GUID directory paths
		HashSet<string> guidDirectories = FindAllGUIDDirectoryPaths(extractedFiles, baselineRootPath);

		List<VerificationResult> allResults = [];

		// Collect all policy files
		List<InMemoryFile> machinePolicyFiles = [];
		List<InMemoryFile> userPolicyFiles = [];
		List<InMemoryFile> auditCsvFiles = [];
		List<InMemoryFile> securityInfFiles = [];

		// Loop over each GUID directory (aka Group Policy Backup directory)
		foreach (string guidDir in guidDirectories)
		{
			cancellationToken?.ThrowIfCancellationRequested();

			Logger.Write($"Processing GUID directory: {Path.GetFileName(guidDir)}");

			// Find machine registry.pol files
			FindPolicyFiles(extractedFiles, guidDir, "Machine", machinePolicyFiles);

			// Find user registry.pol files
			FindPolicyFiles(extractedFiles, guidDir, "User", userPolicyFiles);

			// Find audit.csv files
			FindAuditCsvFiles(extractedFiles, guidDir, auditCsvFiles);

			// Find GptTmpl.inf files
			FindSecurityInfFiles(extractedFiles, guidDir, securityInfFiles);
		}

		// CSV verification in one thread, everything else in another since they call different APIs.
		Task<List<VerificationResult>> csvVerificationTask = Task.Run(() =>
			VerifyAuditPoliciesFromMemory(auditCsvFiles));

		Task<List<VerificationResult>> otherVerificationTask = Task.Run(() =>
		{
			List<VerificationResult> otherResults = [];

			// Verify Group Policies
			otherResults.AddRange(VerifyGroupPoliciesFromMemory(machinePolicyFiles, userPolicyFiles));

			// Verify INF policies
			otherResults.AddRange(VerifySystemAccessPoliciesFromMemory(securityInfFiles));
			otherResults.AddRange(VerifyPrivilegeRightsPoliciesFromMemory(securityInfFiles));
			otherResults.AddRange(VerifyRegistryValuesPoliciesFromMemory(securityInfFiles));

			return otherResults;
		});

		List<VerificationResult> csvResults = await csvVerificationTask;
		List<VerificationResult> otherResults = await otherVerificationTask;

		// Combine all results
		allResults.AddRange(csvResults);
		allResults.AddRange(otherResults);

		cancellationToken?.ThrowIfCancellationRequested();

		int compliantCount = allResults.Count(r => r.IsCompliant);
		Logger.Write($"Verification completed: {compliantCount}/{allResults.Count} policies are compliant");

		return allResults;
	}

	/// <summary>
	/// Verifies audit policies from CSV files in memory.
	/// </summary>
	/// <param name="auditCsvFiles">List of audit CSV files</param>
	/// <returns>List of verification results for audit policies</returns>
	private static List<VerificationResult> VerifyAuditPoliciesFromMemory(List<InMemoryFile> auditCsvFiles)
	{
		List<VerificationResult> results = [];

		foreach (InMemoryFile csvFile in auditCsvFiles)
		{
			try
			{
				using MemoryStream stream = new(csvFile.Content);
				using StreamReader reader = new(stream, Encoding.UTF8);

				List<CsvAuditPolicyEntry> csvEntries = ParseAuditPolicyCsvFromReader(reader);

				// Get current audit policies
				Guid[] guids = csvEntries.Select(e => e.SubcategoryGuid).ToArray();
				Dictionary<Guid, uint> currentPolicies = AuditPolicyManager.GetSpecificAuditPolicies(guids);

				foreach (CsvAuditPolicyEntry entry in csvEntries)
				{
					bool isCompliant = currentPolicies.TryGetValue(entry.SubcategoryGuid, out uint currentValue) &&
									  currentValue == entry.SettingValue;

					string currentValueStr = currentPolicies.TryGetValue(entry.SubcategoryGuid, out uint value)
						? AuditPolicyInfo.GetAuditSettingDescription(value)
						: "Not Found";

					string expectedValueStr = AuditPolicyInfo.GetAuditSettingDescription(entry.SettingValue);

					results.Add(new VerificationResult(
						friendlyName: entry.SubcategoryName,
						source: SecurityMeasureSource.AuditPolicy,
						isCompliant: isCompliant,
						currentValue: currentValueStr,
						expectedValue: expectedValueStr
					));
				}

				Logger.Write($"Verified {csvEntries.Count} audit policies from {csvFile.RelativePath}");
			}
			catch
			{
				Logger.Write($"Error verifying audit policies from {csvFile.RelativePath}.");
				throw;
			}
		}

		return results;
	}

	/// <summary>
	/// Verifies Group Policies from machine and user policy files in memory.
	/// </summary>
	/// <param name="machinePolicyFiles">List of machine policy files</param>
	/// <param name="userPolicyFiles">List of user policy files</param>
	/// <returns>List of verification results for Group Policies</returns>
	private static List<VerificationResult> VerifyGroupPoliciesFromMemory(List<InMemoryFile> machinePolicyFiles, List<InMemoryFile> userPolicyFiles)
	{
		List<VerificationResult> results = [];

		// Process machine policies
		if (machinePolicyFiles.Count > 0)
		{
			List<RegistryPolicyEntry> machinePolicies = [];
			foreach (InMemoryFile polFile in machinePolicyFiles)
			{
				using MemoryStream stream = new(polFile.Content);
				RegistryPolicyFile policyFile = RegistryPolicyParser.ParseStream(stream);
				machinePolicies.AddRange(policyFile.Entries);
			}

			if (machinePolicies.Count > 0)
			{
				// Use the verification results that return the matched system entry for accurate current-value display.
				Dictionary<RegistryPolicyEntry, (bool IsCompliant, RegistryPolicyEntry? SystemEntry)> verificationResults =
					RegistryPolicyParser.VerifyPoliciesInSystem(machinePolicies, GroupPolicyContext.Machine);

				foreach (KeyValuePair<RegistryPolicyEntry, (bool IsCompliant, RegistryPolicyEntry? SystemEntry)> result in verificationResults)
				{
					// Friendly Name is a combination of KeyName and ValueName for the time being.
					string friendlyName = $"{result.Key.KeyName}\\{result.Key.ValueName}";

					// Expected value is the baseline entry's parsed value.
					string expectedValue = FormatBaselineGroupPolicyValue(result.Key);

					// Current value comes from the matched system entry (if any).
					string currentValue;
					RegistryPolicyEntry? systemEntry = result.Value.SystemEntry;
					if (systemEntry is null)
					{
						currentValue = "Not Found";
					}
					else if (systemEntry.ParsedValue is null)
					{
						// Match the display convention used elsewhere
						currentValue = systemEntry.Type == RegistryValueType.REG_MULTI_SZ ? "" : "0";
					}
					else
					{
						currentValue = FormatRegistryValueForDisplay(systemEntry.ParsedValue, systemEntry.Type);
					}

					results.Add(new VerificationResult(
						friendlyName: friendlyName,
						source: SecurityMeasureSource.GroupPolicy,
						isCompliant: result.Value.IsCompliant,
						currentValue: currentValue,
						expectedValue: expectedValue
					));
				}
			}
		}

		// Process user policies
		if (userPolicyFiles.Count > 0)
		{
			List<RegistryPolicyEntry> userPolicies = [];
			foreach (InMemoryFile polFile in userPolicyFiles)
			{
				using MemoryStream stream = new(polFile.Content);
				RegistryPolicyFile policyFile = RegistryPolicyParser.ParseStream(stream);
				userPolicies.AddRange(policyFile.Entries);
			}

			if (userPolicies.Count > 0)
			{
				// Use the verification results that return the matched system entry for accurate current-value display.
				Dictionary<RegistryPolicyEntry, (bool IsCompliant, RegistryPolicyEntry? SystemEntry)> verificationResults =
					RegistryPolicyParser.VerifyPoliciesInSystem(userPolicies, GroupPolicyContext.User);

				foreach (KeyValuePair<RegistryPolicyEntry, (bool IsCompliant, RegistryPolicyEntry? SystemEntry)> result in verificationResults)
				{
					string friendlyName = $"{result.Key.KeyName}\\{result.Key.ValueName}";

					// Expected value is the baseline entry's parsed value.
					string expectedValue = FormatBaselineGroupPolicyValue(result.Key);

					// Current value comes from the matched system entry (if any).
					string currentValue;
					RegistryPolicyEntry? systemEntry = result.Value.SystemEntry;
					if (systemEntry is null)
					{
						currentValue = "Not Found";
					}
					else if (systemEntry.ParsedValue is null)
					{
						// Match the display convention used elsewhere
						currentValue = systemEntry.Type == RegistryValueType.REG_MULTI_SZ ? "" : "0";
					}
					else
					{
						currentValue = FormatRegistryValueForDisplay(systemEntry.ParsedValue, systemEntry.Type);
					}

					results.Add(new VerificationResult(
						friendlyName: friendlyName,
						source: SecurityMeasureSource.GroupPolicy,
						isCompliant: result.Value.IsCompliant,
						currentValue: currentValue,
						expectedValue: expectedValue
					));
				}
			}
		}

		return results;
	}

	/// <summary>
	/// Verifies System Access policies from INF files in memory.
	/// </summary>
	/// <param name="infFiles">List of INF files</param>
	/// <returns>List of verification results for System Access policies</returns>
	private static List<VerificationResult> VerifySystemAccessPoliciesFromMemory(List<InMemoryFile> infFiles)
	{
		List<VerificationResult> results = [];

		// Extract expected system access settings from INF files
		Dictionary<string, string> expectedSettings = [];
		foreach (InMemoryFile infFile in infFiles)
		{
			using MemoryStream stream = new(infFile.Content);
			using StreamReader reader = new(stream, Encoding.UTF8);

			Dictionary<string, string> temp = SecurityPolicyManager.ExtractSystemAccessSettingsFromReader(reader);
			foreach (KeyValuePair<string, string> item in temp)
			{
				expectedSettings[item.Key] = item.Value;
			}
		}

		if (expectedSettings.Count == 0)
			return results;

		// Get current system access settings
		SystemAccessInfo currentSystemAccess = SecurityPolicyReader.GetSystemAccess();

		// Verify each expected setting
		foreach (KeyValuePair<string, string> expectedSetting in expectedSettings)
		{
			bool isCompliant;
			string currentValue;
			string expectedValue = expectedSetting.Value;

			// Map setting name to actual property and compare
			// This is because SystemAccessInfo is a class and not Dictionary<string, string>
			switch (expectedSetting.Key)
			{
				case "MinimumPasswordAge":
					currentValue = currentSystemAccess.MinimumPasswordAge.ToString(CultureInfo.InvariantCulture);
					isCompliant = int.Parse(expectedSetting.Value, CultureInfo.InvariantCulture) == currentSystemAccess.MinimumPasswordAge;
					break;
				case "MaximumPasswordAge":
					currentValue = currentSystemAccess.MaximumPasswordAge.ToString(CultureInfo.InvariantCulture);
					isCompliant = int.Parse(expectedSetting.Value, CultureInfo.InvariantCulture) == currentSystemAccess.MaximumPasswordAge;
					break;
				case "MinimumPasswordLength":
					currentValue = currentSystemAccess.MinimumPasswordLength.ToString(CultureInfo.InvariantCulture);
					isCompliant = int.Parse(expectedSetting.Value, CultureInfo.InvariantCulture) == currentSystemAccess.MinimumPasswordLength;
					break;
				case "PasswordComplexity":
					currentValue = currentSystemAccess.PasswordComplexity.ToString(CultureInfo.InvariantCulture);
					isCompliant = int.Parse(expectedSetting.Value, CultureInfo.InvariantCulture) == currentSystemAccess.PasswordComplexity;
					break;
				case "PasswordHistorySize":
					currentValue = currentSystemAccess.PasswordHistorySize.ToString(CultureInfo.InvariantCulture);
					isCompliant = int.Parse(expectedSetting.Value, CultureInfo.InvariantCulture) == currentSystemAccess.PasswordHistorySize;
					break;
				case "LockoutBadCount":
					currentValue = currentSystemAccess.LockoutBadCount.ToString(CultureInfo.InvariantCulture);
					isCompliant = int.Parse(expectedSetting.Value, CultureInfo.InvariantCulture) == currentSystemAccess.LockoutBadCount;
					break;
				case "ResetLockoutCount":
					currentValue = currentSystemAccess.ResetLockoutCount.ToString(CultureInfo.InvariantCulture);
					isCompliant = int.Parse(expectedSetting.Value, CultureInfo.InvariantCulture) == currentSystemAccess.ResetLockoutCount;
					break;
				case "LockoutDuration":
					currentValue = currentSystemAccess.LockoutDuration.ToString(CultureInfo.InvariantCulture);
					isCompliant = int.Parse(expectedSetting.Value, CultureInfo.InvariantCulture) == currentSystemAccess.LockoutDuration;
					break;
				case "AllowAdministratorLockout":
					currentValue = currentSystemAccess.AllowAdministratorLockout.ToString(CultureInfo.InvariantCulture);
					isCompliant = int.Parse(expectedSetting.Value, CultureInfo.InvariantCulture) == currentSystemAccess.AllowAdministratorLockout;
					break;
				case "RequireLogonToChangePassword":
					currentValue = currentSystemAccess.RequireLogonToChangePassword.ToString(CultureInfo.InvariantCulture);
					isCompliant = int.Parse(expectedSetting.Value, CultureInfo.InvariantCulture) == currentSystemAccess.RequireLogonToChangePassword;
					break;
				case "ForceLogoffWhenHourExpire":
					currentValue = currentSystemAccess.ForceLogoffWhenHourExpire.ToString(CultureInfo.InvariantCulture);
					isCompliant = int.Parse(expectedSetting.Value, CultureInfo.InvariantCulture) == currentSystemAccess.ForceLogoffWhenHourExpire;
					break;
				case "NewAdministratorName":
					currentValue = currentSystemAccess.NewAdministratorName;
					isCompliant = string.Equals(expectedSetting.Value.Trim('"'), currentSystemAccess.NewAdministratorName, StringComparison.OrdinalIgnoreCase);
					break;
				case "NewGuestName":
					currentValue = currentSystemAccess.NewGuestName;
					isCompliant = string.Equals(expectedSetting.Value.Trim('"'), currentSystemAccess.NewGuestName, StringComparison.OrdinalIgnoreCase);
					break;
				case "ClearTextPassword":
					currentValue = currentSystemAccess.ClearTextPassword.ToString(CultureInfo.InvariantCulture);
					isCompliant = int.Parse(expectedSetting.Value, CultureInfo.InvariantCulture) == currentSystemAccess.ClearTextPassword;
					break;
				case "EnableAdminAccount":
					currentValue = currentSystemAccess.EnableAdminAccount.ToString(CultureInfo.InvariantCulture);
					isCompliant = int.Parse(expectedSetting.Value, CultureInfo.InvariantCulture) == currentSystemAccess.EnableAdminAccount;
					break;
				case "EnableGuestAccount":
					currentValue = currentSystemAccess.EnableGuestAccount.ToString(CultureInfo.InvariantCulture);
					isCompliant = int.Parse(expectedSetting.Value, CultureInfo.InvariantCulture) == currentSystemAccess.EnableGuestAccount;
					break;
				case "LSAAnonymousNameLookup":
					currentValue = currentSystemAccess.LSAAnonymousNameLookup.ToString(CultureInfo.InvariantCulture);
					isCompliant = int.Parse(expectedSetting.Value, CultureInfo.InvariantCulture) == currentSystemAccess.LSAAnonymousNameLookup;
					break;
				default:
					currentValue = "Unknown Setting";
					isCompliant = false;
					break;
			}

			results.Add(new VerificationResult(
				friendlyName: expectedSetting.Key,
				source: SecurityMeasureSource.SystemAccess,
				isCompliant: isCompliant,
				currentValue: currentValue,
				expectedValue: expectedValue
			));
		}

		return results;
	}

	/// <summary>
	/// Verifies Privilege Rights policies from INF files in memory.
	/// </summary>
	/// <param name="infFiles">List of INF files</param>
	/// <returns>List of verification results for Privilege Rights policies</returns>
	private static List<VerificationResult> VerifyPrivilegeRightsPoliciesFromMemory(List<InMemoryFile> infFiles)
	{
		List<VerificationResult> results = [];

		// Extract expected privilege rights from INF files
		Dictionary<string, string[]> expectedPrivileges = new(StringComparer.Ordinal);
		foreach (InMemoryFile infFile in infFiles)
		{
			using MemoryStream stream = new(infFile.Content);
			using StreamReader reader = new(stream, Encoding.UTF8);

			ParsedInfData fileData = ParseSingleInfFileFromReader(reader);
			foreach (KeyValuePair<string, string[]> privilege in fileData.PrivilegeRights)
			{
				expectedPrivileges[privilege.Key] = privilege.Value;
			}
		}

		if (expectedPrivileges.Count == 0)
			return results;

		// Get current privilege rights of the system.
		Dictionary<string, string[]> currentPrivileges = SecurityPolicyReader.GetPrivilegeRights();

		// Verify each expected privilege		
		foreach (KeyValuePair<string, string[]> expectedPrivilege in expectedPrivileges)
		{
			bool isCompliant;
			string currentValue;

			// Normalize expected assignments (from INF) to plain SID strings.
			// This allows INF tokens to be SIDs with or without '*', or account names (e.g., NewGuestNamev5).
			List<string> normalizedList = [];
			foreach (string token in expectedPrivilege.Value)
			{
				string normalized = SecurityPolicyWriter.GetNormalizedSidString(token);
				if (string.IsNullOrEmpty(normalized))
				{
					Logger.Write($"Privilege SID normalization failed for token '{token}' in privilege '{expectedPrivilege.Key}'.");
					continue;
				}
				normalizedList.Add(normalized);
			}
			string[] normalizedExpectedPlain = normalizedList.ToArray();

			// For display, mirror the system's shape ("*SID") while the comparison uses plain SIDs.
			string expectedValue = normalizedExpectedPlain.Length == 0
				? "(No assignments)"
				: string.Join(", ", normalizedExpectedPlain.Select(s => s.StartsWith("S-", StringComparison.OrdinalIgnoreCase) ? "*" + s : s));

			if (currentPrivileges.TryGetValue(expectedPrivilege.Key, out string[]? currentSids))
			{
				currentValue = currentSids.Length == 0 ? "(No assignments)" : string.Join(", ", currentSids);

				if (normalizedExpectedPlain.Length == 0)
				{
					// Expected no assignments - compliant if current also has no assignments
					isCompliant = currentSids.Length == 0;
				}
				else
				{
					// Expected specific assignments - exact match required
					// But the location of the SIDs in the array does not and should never matter.

					// Normalize current system SIDs to plain form by stripping the leading '*'
					string[] normalizedCurrentPlain = currentSids
						.Select(s => s.StartsWith('*') ? s[1..] : s)
						.ToArray();

					isCompliant =
						normalizedExpectedPlain.Length == normalizedCurrentPlain.Length &&
						normalizedExpectedPlain.All(expected => normalizedCurrentPlain.Contains(expected, StringComparer.OrdinalIgnoreCase));
				}
			}
			else
			{
				// Privilege not found on system
				currentValue = "Not Found";

				if (normalizedExpectedPlain.Length == 0)
				{
					// Expected no assignments and privilege not found - this is compliant
					isCompliant = true;
				}
				else
				{
					// Expected specific assignments but privilege not found - not compliant
					isCompliant = false;
				}
			}

			results.Add(new VerificationResult(
				friendlyName: expectedPrivilege.Key,
				source: SecurityMeasureSource.Privilege,
				isCompliant: isCompliant,
				currentValue: currentValue,
				expectedValue: expectedValue
			));
		}

		return results;
	}

	/// <summary>
	/// Verifies Registry Values policies from INF files in memory.
	/// </summary>
	/// <param name="infFiles">List of INF files</param>
	/// <returns>List of verification results for Registry Values policies</returns>
	private static List<VerificationResult> VerifyRegistryValuesPoliciesFromMemory(List<InMemoryFile> infFiles)
	{
		List<VerificationResult> results = [];

		// Extract expected registry policies from INF files
		List<RegistryPolicyEntry> expectedPolicies = [];
		foreach (InMemoryFile infFile in infFiles)
		{
			using MemoryStream stream = new(infFile.Content);
			using StreamReader reader = new(stream, Encoding.UTF8);

			ParsedInfData fileData = ParseSingleInfFileFromReader(reader);
			expectedPolicies.AddRange(fileData.RegistryPolicyEntries);
		}

		if (expectedPolicies.Count == 0)
			return results;

		// Verify each policy individually
		foreach (RegistryPolicyEntry policy in expectedPolicies)
		{
			string expectedValue = policy.RegValue ?? "Unknown";

			// Use centralized Manager logic for reading and comparing registry values.
			bool isCompliant;
			string currentValue = "Not Found";

			// Manager returns canonical strings (e.g., Base64 for binary, ";" for multi-sz)
			string? actual = RegistryManager.Manager.ReadRegistry(policy);

			if (actual is not null && policy.RegValue is not null)
			{
				isCompliant = RegistryManager.Manager.CompareRegistryValues(policy.Type, actual, policy.RegValue);
				currentValue = actual;
			}
			else
			{
				// Keep "Not Found" for missing key/value; no extra key probing to avoid unnecessary changes.
				isCompliant = false;
			}

			results.Add(new VerificationResult(
				friendlyName: policy.KeyName,
				source: SecurityMeasureSource.SecurityPolicyRegistry,
				isCompliant: isCompliant,
				currentValue: currentValue,
				expectedValue: expectedValue
			));
		}

		return results;
	}

	/// <summary>
	/// Gets the current value of a Group Policy registry entry for display purposes.
	/// </summary>
	/// <param name="policy">The policy entry</param>
	/// <returns>String representation of the current value</returns>
	private static string FormatBaselineGroupPolicyValue(RegistryPolicyEntry policy)
	{
		try
		{
			// Return the expected value from the policy as string representation
			// This provides meaningful information for display
			return policy.ParsedValue switch
			{
				null => "No Value",
				string str => str,
				byte[] bytes => Convert.ToBase64String(bytes),
				ReadOnlyMemory<byte> rom => rom.IsEmpty ? string.Empty : Convert.ToBase64String(rom.Span),
				string[] strings => string.Join(", ", strings),
				_ => policy.ParsedValue.ToString() ?? "Unknown"
			};
		}
		catch (Exception ex)
		{
			return $"Error Reading Value: {ex.Message}";
		}
	}

	/// <summary>
	/// Formats a registry value for display based on its type, matching SecurityPolicyReader formatting.
	/// </summary>
	/// <param name="value">The registry value</param>
	/// <param name="type">The registry value type</param>
	/// <returns>Formatted string representation</returns>
	private static string FormatRegistryValueForDisplay(object value, RegistryValueType type)
	{
		switch (type)
		{
			case RegistryValueType.REG_SZ:
				{
					return $"\"{value}\"";
				}
			case RegistryValueType.REG_BINARY:
				{
					if (value is byte[] bytes)
					{
						return bytes.Length == 0 ? string.Empty : string.Join(",", bytes);
					}
					if (value is ReadOnlyMemory<byte> rom)
					{
						if (rom.IsEmpty)
						{
							return string.Empty;
						}
						return string.Join(',', rom.ToArray());
					}
					return value?.ToString() ?? string.Empty;
				}
			case RegistryValueType.REG_DWORD:
				{
					return value.ToString() ?? "0";
				}
			case RegistryValueType.REG_MULTI_SZ:
				{
					return value is string[] strings ? string.Join("\n", strings) : value.ToString() ?? "";
				}

			case RegistryValueType.REG_FULL_RESOURCE_DESCRIPTOR:
			case RegistryValueType.REG_NONE:
			case RegistryValueType.REG_EXPAND_SZ:
			case RegistryValueType.REG_DWORD_BIG_ENDIAN:
			case RegistryValueType.REG_LINK:
			case RegistryValueType.REG_RESOURCE_LIST:
			case RegistryValueType.REG_RESOURCE_REQUIREMENTS_LIST:
			case RegistryValueType.REG_QWORD:
			default:
				{
					return value.ToString() ?? "";
				}
		}
	}

	/// <summary>
	/// Finds and applies or removes all security baseline policies from memory based on the specified action.
	/// </summary>
	/// <param name="extractedFiles">List of extracted files</param>
	/// <param name="baselineRootPath">Root path of the security baseline</param>
	/// <param name="action">Whether to apply or remove the policies</param>
	private static void ApplyOrRemoveSecurityBaselinePolicies(List<InMemoryFile> extractedFiles, string baselineRootPath, PolicyAction action, CancellationToken? cancellationToken = null)
	{
		// Find all GUID directory paths
		HashSet<string> guidDirectories = FindAllGUIDDirectoryPaths(extractedFiles, baselineRootPath);

		// Collect all policy files
		List<InMemoryFile> machinePolicyFiles = [];
		List<InMemoryFile> userPolicyFiles = [];
		List<InMemoryFile> auditCsvFiles = [];
		List<InMemoryFile> securityInfFiles = [];

		// Loop over each GUID directory (aka Group Policy Backup directory)
		foreach (string guidDir in guidDirectories)
		{
			cancellationToken?.ThrowIfCancellationRequested();

			Logger.Write($"Processing GUID directory: {Path.GetFileName(guidDir)}");

			// Find machine registry.pol files
			FindPolicyFiles(extractedFiles, guidDir, "Machine", machinePolicyFiles);

			// Find user registry.pol files
			FindPolicyFiles(extractedFiles, guidDir, "User", userPolicyFiles);

			// Don't process audit CSV files or security INF files during removal.
			if (action == PolicyAction.Apply)
			{
				// Find audit.csv files
				FindAuditCsvFiles(extractedFiles, guidDir, auditCsvFiles);

				cancellationToken?.ThrowIfCancellationRequested();

				// Find GptTmpl.inf files
				FindSecurityInfFiles(extractedFiles, guidDir, securityInfFiles);
			}
		}

		cancellationToken?.ThrowIfCancellationRequested();

		// Apply or remove all found policies based on action
		ApplyOrRemoveFoundPolicies(machinePolicyFiles, userPolicyFiles, auditCsvFiles, securityInfFiles, action, cancellationToken);
	}

	/// <summary>
	/// Checks if a directory name is a valid GUID format.
	/// </summary>
	/// <param name="directoryName">Directory name to check</param>
	/// <returns>True if directory name is a valid GUID format</returns>
	private static bool IsGuidDirectory(string directoryName)
	{
		return directoryName.StartsWith('{') &&
			   directoryName.EndsWith('}') &&
			   Guid.TryParse(directoryName, CultureInfo.InvariantCulture, out _);
	}

	/// <summary>
	/// Finds registry.pol files for the specified context (Machine or User) from memory.
	/// </summary>
	/// <param name="extractedFiles">List of extracted files</param>
	/// <param name="guidDir">GUID directory path</param>
	/// <param name="context">Context (Machine or User)</param>
	/// <param name="policyFiles">List to add found policy files to</param>
	private static void FindPolicyFiles(List<InMemoryFile> extractedFiles, string guidDir, string context, List<InMemoryFile> policyFiles)
	{
		try
		{
			// Expected path: {GUID}\DomainSysvol\GPO\{context}\registry.pol
			string[] pathSegments = ["DomainSysvol", "GPO", context, "registry.pol"];
			InMemoryFile? policyFile = FindFileByPath(extractedFiles, guidDir, pathSegments);

			if (policyFile is not null)
			{
				policyFiles.Add(policyFile);
				Logger.Write($"Found {context} policy file: {policyFile.RelativePath}");
			}
		}
		catch (Exception ex)
		{
			Logger.Write($"Warning: Error searching for {context} policy files in {guidDir}: {ex.Message}");
		}
	}

	/// <summary>
	/// Finds audit.csv files from memory.
	/// </summary>
	/// <param name="extractedFiles">List of extracted files</param>
	/// <param name="guidDir">GUID directory path</param>
	/// <param name="auditCsvFiles">List to add found audit CSV files to</param>
	private static void FindAuditCsvFiles(List<InMemoryFile> extractedFiles, string guidDir, List<InMemoryFile> auditCsvFiles)
	{
		try
		{
			// Expected path: {GUID}\DomainSysvol\GPO\Machine\microsoft\windows nt\Audit\audit.csv
			string[] pathSegments = ["DomainSysvol", "GPO", "Machine", "microsoft", "windows nt", "Audit", "audit.csv"];
			InMemoryFile? auditCsvFile = FindFileByPath(extractedFiles, guidDir, pathSegments);

			if (auditCsvFile is not null)
			{
				auditCsvFiles.Add(auditCsvFile);
				Logger.Write($"Found audit CSV file: {auditCsvFile.RelativePath}");
			}
		}
		catch (Exception ex)
		{
			Logger.Write($"Warning: Error searching for audit CSV files in {guidDir}: {ex.Message}");
		}
	}

	/// <summary>
	/// Finds GptTmpl.inf files from memory.
	/// </summary>
	/// <param name="extractedFiles">List of extracted files</param>
	/// <param name="guidDir">GUID directory path</param>
	/// <param name="securityInfFiles">List to add found security INF files to</param>
	private static void FindSecurityInfFiles(List<InMemoryFile> extractedFiles, string guidDir, List<InMemoryFile> securityInfFiles)
	{
		try
		{
			// Expected path: {GUID}\DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf
			string[] pathSegments = ["DomainSysvol", "GPO", "Machine", "microsoft", "windows nt", "SecEdit", "GptTmpl.inf"];
			InMemoryFile? infFile = FindFileByPath(extractedFiles, guidDir, pathSegments);

			if (infFile is not null)
			{
				securityInfFiles.Add(infFile);
				Logger.Write($"Found security INF file: {infFile.RelativePath}");
			}
		}
		catch (Exception ex)
		{
			Logger.Write($"Warning: Error searching for security INF files in {guidDir}: {ex.Message}");
		}
	}

	/// <summary>
	/// Finds a file by following a path of directory segments from memory.
	/// </summary>
	/// <param name="extractedFiles">List of extracted files</param>
	/// <param name="rootDir">Root directory to start search from</param>
	/// <param name="pathSegments">Array of path segments to follow</param>
	/// <returns>InMemoryFile if found, null otherwise</returns>
	private static InMemoryFile? FindFileByPath(List<InMemoryFile> extractedFiles, string rootDir, string[] pathSegments)
	{
		string normalizedRootDir = rootDir.Replace('\\', '/');
		if (!normalizedRootDir.EndsWith('/'))
			normalizedRootDir += '/';

		string expectedPath = normalizedRootDir + string.Join('/', pathSegments);

		return extractedFiles.FirstOrDefault(file =>
			string.Equals(file.RelativePath.Replace('\\', '/'), expectedPath, StringComparison.OrdinalIgnoreCase));
	}

	/// <summary>
	/// Applies or removes all found policy files from memory based on the specified action.
	/// </summary>
	/// <param name="machinePolicyFiles">List of machine policy files</param>
	/// <param name="userPolicyFiles">List of user policy files</param>
	/// <param name="auditCsvFiles">List of audit CSV files</param>
	/// <param name="securityInfFiles">List of security INF files</param>
	/// <param name="action">Whether to apply or remove the policies</param>
	private static void ApplyOrRemoveFoundPolicies(List<InMemoryFile> machinePolicyFiles, List<InMemoryFile> userPolicyFiles,
		List<InMemoryFile> auditCsvFiles, List<InMemoryFile> securityInfFiles, PolicyAction action, CancellationToken? cancellationToken = null)
	{
		string actionText = action == PolicyAction.Apply ? "Applying" : "Removing";
		Logger.Write($"{actionText} security baseline policies:");
		Logger.Write($"  Machine POL files: {machinePolicyFiles.Count}");
		Logger.Write($"  User POL files: {userPolicyFiles.Count}");

		if (action == PolicyAction.Apply)
		{
			Logger.Write($"  Audit CSV files: {auditCsvFiles.Count}");
			Logger.Write($"  Security INF files: {securityInfFiles.Count}");
		}
		else
		{
			Logger.Write($"  Audit CSV files: {auditCsvFiles.Count} (skipped during removal)");
			Logger.Write($"  Security INF files: {securityInfFiles.Count} (skipped during removal)");
		}

		cancellationToken?.ThrowIfCancellationRequested();

		// Process machine POL files
		if (machinePolicyFiles.Count > 0)
		{
			Logger.Write($"{actionText} machine POL files...");
			ProcessPolFilesFromMemory(GroupPolicyContext.Machine, machinePolicyFiles, action);
		}

		cancellationToken?.ThrowIfCancellationRequested();

		// Process user POL files
		if (userPolicyFiles.Count > 0)
		{
			Logger.Write($"{actionText} user POL files...");
			ProcessPolFilesFromMemory(GroupPolicyContext.User, userPolicyFiles, action);
		}

		cancellationToken?.ThrowIfCancellationRequested();

		// Only process audit CSV and security INF files when applying (not when removing)
		if (action == PolicyAction.Apply)
		{
			// Apply audit CSV files
			if (auditCsvFiles.Count > 0)
			{
				Logger.Write("Applying audit CSV files...");
				foreach (InMemoryFile auditCsvFile in auditCsvFiles)
				{
					cancellationToken?.ThrowIfCancellationRequested();

					ApplyAuditPoliciesFromMemory(auditCsvFile);
					Logger.Write($"Applied audit policies from: {auditCsvFile.RelativePath}");
				}
			}

			// Apply security INF files
			if (securityInfFiles.Count > 0)
			{
				cancellationToken?.ThrowIfCancellationRequested();

				Logger.Write("Applying security INF files...");
				ParseAndApplyInfFilesFromMemory(securityInfFiles);
			}
		}

		string completionText = action == PolicyAction.Apply ? "applied" : "removed";
		Logger.Write($"All security baseline policies {completionText} successfully");
	}

	/// <summary>
	/// Processes one or more POL files from memory to the system with the specified Group Policy context.
	/// Can either apply or remove the policies based on the action parameter.
	/// </summary>
	/// <param name="context">The Group Policy context (Machine or User) for the POL files</param>
	/// <param name="polFiles">In-memory POL files to process</param>
	/// <param name="action">Whether to apply or remove the policies</param>
	/// <exception cref="ArgumentException">Thrown when no files are provided</exception>
	private static void ProcessPolFilesFromMemory(GroupPolicyContext context, List<InMemoryFile> polFiles, PolicyAction action)
	{
		string actionText = action == PolicyAction.Apply ? "apply" : "remove";
		Logger.Write($"Starting to {actionText} {polFiles.Count} POL file(s) in {context} context from memory");

		List<RegistryPolicyEntry> accumulatedPolicies = [];

		// Parse each POL file and accumulate entries
		foreach (InMemoryFile polFile in polFiles)
		{
			Logger.Write($"Parsing POL file from memory: {polFile.RelativePath}");

			using MemoryStream stream = new(polFile.Content);
			RegistryPolicyFile policyFile = RegistryPolicyParser.ParseStream(stream);

			Logger.Write($"Loaded {policyFile.Entries.Count} policy entries from {polFile.RelativePath}");

			accumulatedPolicies.AddRange(policyFile.Entries);
		}

		Logger.Write($"Total accumulated policies to {actionText}: {accumulatedPolicies.Count}");

		// Apply or remove all accumulated policies to/from the system with the specified context
		if (action == PolicyAction.Apply)
		{
			RegistryPolicyParser.AddPoliciesToSystem(accumulatedPolicies, context);
		}
		else
		{
			RegistryPolicyParser.RemovePoliciesFromSystem(accumulatedPolicies, context);
		}

		Logger.Write($"POL files {actionText} completed successfully in {context} context");
	}

	/// <summary>
	/// Applies audit policies from a CSV file in memory to the system.
	/// </summary>
	/// <param name="csvFile">In-memory CSV file containing audit policies</param>
	/// <exception cref="InvalidOperationException">Thrown when policy application fails</exception>
	private static void ApplyAuditPoliciesFromMemory(InMemoryFile csvFile)
	{
		using MemoryStream stream = new(csvFile.Content);
		using StreamReader reader = new(stream, Encoding.UTF8);

		List<CsvAuditPolicyEntry> csvEntries = ParseAuditPolicyCsvFromReader(reader);

		// Apply the audit policies
		AuditPolicyManager.SetAuditPolicies(AuditPolicyManager.ConvertCSVEntriesToAuditPolicyInfo(csvEntries));

		Logger.Write($"Successfully applied {csvEntries.Count} audit policies from {csvFile.RelativePath}");
	}

	/// <summary>
	/// Parses one or more INF files from memory and applies all supported sections to the system.
	/// </summary>
	/// <param name="infFiles">In-memory INF files to parse and apply</param>
	/// <exception cref="ArgumentException">Thrown when no files are provided</exception>
	/// <exception cref="InvalidOperationException">Thrown when application fails</exception>
	private static void ParseAndApplyInfFilesFromMemory(List<InMemoryFile> infFiles)
	{
		Logger.Write($"Starting to parse and apply {infFiles.Count} INF file(s) from memory");

		// Apply System Access policies from all INF files at once
		Dictionary<string, string> systemAccessSettings = [];

		foreach (InMemoryFile infFile in infFiles)
		{
			Logger.Write($"Finding System Access policies in: {infFile.RelativePath}");

			using MemoryStream stream = new(infFile.Content);
			using StreamReader reader = new(stream, Encoding.UTF8);

			Dictionary<string, string> temp = SecurityPolicyManager.ExtractSystemAccessSettingsFromReader(reader);

			if (temp.Count > 0)
			{
				foreach (KeyValuePair<string, string> item in temp)
				{
					systemAccessSettings[item.Key] = item.Value;
				}
			}
		}

		if (systemAccessSettings.Count > 0)
		{
			ApplySystemAccessSettings(systemAccessSettings);
			Logger.Write($"{systemAccessSettings.Count} System Access policies applied successfully.");
		}

		// Parse all INF files and accumulate their data that are not System Access since we already applied those above.
		ParsedInfData parsedData = ParseInfFilesFromMemory(infFiles);

		// Apply Privilege Rights policies
		if (parsedData.PrivilegeRights.Count > 0)
		{
			Logger.Write("Applying Privilege Rights policies...");
			SecurityPolicyWriter.SetPrivilegeRights(parsedData.PrivilegeRights);
			Logger.Write("Privilege Rights policies applied successfully");
		}

		// Apply Registry Policy Entries
		if (parsedData.RegistryPolicyEntries.Count > 0)
		{
			Logger.Write("Applying Registry Policy Entries...");
			RegistryManager.Manager.AddPoliciesToSystem(parsedData.RegistryPolicyEntries);
			Logger.Write("Registry Policy Entries applied successfully");
		}

		Logger.Write("INF files application completed successfully");
	}

	/// <summary>
	/// Parses one or more INF files from memory and accumulates their data, extracting Privilege Rights and Registry Values sections.
	/// </summary>
	/// <param name="infFiles">In-memory INF files to parse</param>
	/// <returns>Accumulated parsed INF data structure</returns>
	private static ParsedInfData ParseInfFilesFromMemory(List<InMemoryFile> infFiles)
	{
		Dictionary<string, string[]> privilegeRights = new(StringComparer.Ordinal);
		List<RegistryPolicyEntry> registryPolicyEntries = [];

		foreach (InMemoryFile infFile in infFiles)
		{
			Logger.Write($"Parsing INF file from memory: {infFile.RelativePath}");

			using MemoryStream stream = new(infFile.Content);
			using StreamReader reader = new(stream, Encoding.UTF8);

			ParsedInfData fileData = ParseSingleInfFileFromReader(reader);

			// Accumulate Privilege Rights (later files override earlier ones for same privileges)
			foreach (KeyValuePair<string, string[]> privilege in fileData.PrivilegeRights)
			{
				privilegeRights[privilege.Key] = privilege.Value;
			}

			// Accumulate Registry Policy Entries (later files override earlier ones for same registry paths)
			foreach (RegistryPolicyEntry entry in fileData.RegistryPolicyEntries)
			{
				// Remove any existing entry with the same KeyName and ValueName to avoid duplicates
				_ = registryPolicyEntries.RemoveAll(existing =>
					string.Equals(existing.KeyName, entry.KeyName, StringComparison.OrdinalIgnoreCase) &&
					string.Equals(existing.ValueName, entry.ValueName, StringComparison.OrdinalIgnoreCase));

				// Add the new registry policy entry
				registryPolicyEntries.Add(entry);
			}

			Logger.Write($"Parsed {fileData.PrivilegeRights.Count} Privilege Rights, {fileData.RegistryPolicyEntries.Count} Registry Policy Entries from {infFile.RelativePath}");
		}

		Logger.Write($"Total accumulated: {privilegeRights.Count} Privilege Rights, {registryPolicyEntries.Count} Registry Policy Entries");

		return new(privilegeRights: privilegeRights, registryPolicyEntries: registryPolicyEntries);
	}

	/// <summary>
	/// Parses a single INF file from a StreamReader and extracts Privilege Rights and Registry Values sections.
	/// </summary>
	/// <param name="reader">StreamReader for the INF content</param>
	/// <returns>Parsed INF data structure</returns>
	private static ParsedInfData ParseSingleInfFileFromReader(StreamReader reader)
	{
		Dictionary<string, string[]> privilegeRights = new(StringComparer.Ordinal);
		List<RegistryPolicyEntry> registryPolicyEntries = [];

		string currentSection = string.Empty;
		string? line;

		while ((line = reader.ReadLine()) is not null)
		{
			string trimmedLine = line.Trim();

			// Skip empty lines and comments
			if (string.IsNullOrEmpty(trimmedLine) || trimmedLine.StartsWith(';'))
				continue;

			// Check for section headers
			if (trimmedLine.StartsWith('[') && trimmedLine.EndsWith(']'))
			{
				currentSection = trimmedLine[1..^1];
				continue;
			}

			// Parse content based on current section
			switch (currentSection.ToLowerInvariant())
			{
				case "privilege rights":
					ParsePrivilegeRightsLine(trimmedLine, privilegeRights);
					break;
				case "registry values":
					RegistryPolicyEntry? parsedEntry = SecurityINFParser.ParseRegistryValueLine(trimmedLine);
					if (parsedEntry is not null) registryPolicyEntries.Add(parsedEntry);
					break;
				default:
					break;
			}
		}

		return new(privilegeRights: privilegeRights, registryPolicyEntries: registryPolicyEntries);
	}

	/// <summary>
	/// Parses a CSV reader containing audit policy settings.
	/// </summary>
	/// <param name="reader">StreamReader for the CSV content</param>
	/// <returns>List of CSV audit policy entries</returns>
	/// <exception cref="InvalidDataException">Thrown when CSV format is invalid</exception>
	private static List<CsvAuditPolicyEntry> ParseAuditPolicyCsvFromReader(StreamReader reader)
	{
		List<CsvAuditPolicyEntry> entries = [];
		List<string> lines = [];

		string? line;
		while ((line = reader.ReadLine()) is not null)
		{
			lines.Add(line);
		}

		if (lines.Count < 2)
			throw new InvalidDataException("CSV content must contain at least a header and one data row");

		// Skip header row (index 0)
		for (int i = 1; i < lines.Count; i++)
		{
			string currentLine = lines[i].Trim();
			if (string.IsNullOrEmpty(currentLine))
				continue;

			try
			{
				CsvAuditPolicyEntry? entry = AuditPolicyManager.ParseCsvLine(currentLine, i + 1);
				if (entry is not null)
				{
					entries.Add(entry);
				}
			}
			catch (Exception ex)
			{
				throw new InvalidDataException($"Error parsing CSV line {i + 1}: {ex.Message}", ex);
			}
		}

		if (entries.Count == 0)
		{
			throw new InvalidDataException("No valid audit policy entries found in CSV content");
		}

		Logger.Write($"Parsed {entries.Count} audit policy entries from CSV");
		return entries;
	}

	/// <summary>
	/// Parses a single line from the [Privilege Rights] section.
	/// </summary>
	/// <param name="line">Line to parse</param>
	/// <param name="privilegeRights">Dictionary to store parsed values</param>
	private static void ParsePrivilegeRightsLine(string line, Dictionary<string, string[]> privilegeRights)
	{
		int equalsIndex = line.IndexOf('=');
		if (equalsIndex == -1)
			return;

		string privilege = line[..equalsIndex].Trim();
		string rightsString = line[(equalsIndex + 1)..].Trim();

		// Split by comma and filter out empty entries
		string[] rights = string.IsNullOrEmpty(rightsString)
			? []
			: rightsString.Split(',', StringSplitOptions.RemoveEmptyEntries)
				.Select(r => r.Trim())
				.Where(r => !string.IsNullOrEmpty(r))
				.ToArray();

		privilegeRights[privilege] = rights;
	}

	#region File Based Methods

	/// <summary>
	/// Parses one or more INF files and accumulates their data, extracting Privilege Rights and Registry Values sections.
	/// </summary>
	/// <param name="filePaths">Paths to one or more INF files</param>
	/// <returns>Accumulated parsed INF data structure</returns>
	/// <exception cref="ArgumentException">Thrown when no file paths are provided</exception>
	/// <exception cref="FileNotFoundException">Thrown when any file doesn't exist</exception>
	private static ParsedInfData ParseInfFiles(params string[] filePaths)
	{
		if (filePaths.Length is 0)
			throw new ArgumentException("At least one INF file path must be provided");

		Dictionary<string, string[]> privilegeRights = new(StringComparer.Ordinal);
		List<RegistryPolicyEntry> registryPolicyEntries = [];

		foreach (string filePath in filePaths)
		{
			Logger.Write($"Parsing INF file: {filePath}");

			List<RegistryPolicyEntry> fileRegistryEntries = SecurityINFParser.ParseSecurityINFFile(filePath);

			// Parse privilege rights manually since SecurityINFParser doesn't handle that section
			using FileStream fileStream = new(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
			using StreamReader reader = new(fileStream, Encoding.UTF8);

			ParsedInfData fileData = ParseSingleInfFileFromReader(reader);

			// Accumulate Privilege Rights (later files override earlier ones for same privileges)
			foreach (KeyValuePair<string, string[]> privilege in fileData.PrivilegeRights)
			{
				privilegeRights[privilege.Key] = privilege.Value;
			}

			// Accumulate Registry Policy Entries from SecurityINFParser
			foreach (RegistryPolicyEntry entry in fileRegistryEntries)
			{
				// Remove any existing entry with the same KeyName and ValueName to avoid duplicates
				_ = registryPolicyEntries.RemoveAll(existing =>
					string.Equals(existing.KeyName, entry.KeyName, StringComparison.OrdinalIgnoreCase) &&
					string.Equals(existing.ValueName, entry.ValueName, StringComparison.OrdinalIgnoreCase));

				// Add the new registry policy entry
				registryPolicyEntries.Add(entry);
			}

			Logger.Write($"Parsed {fileData.PrivilegeRights.Count} Privilege Rights, {fileRegistryEntries.Count} Registry Policy Entries from {filePath}");
		}

		Logger.Write($"Total accumulated: {privilegeRights.Count} Privilege Rights, {registryPolicyEntries.Count} Registry Policy Entries");

		return new(privilegeRights: privilegeRights, registryPolicyEntries: registryPolicyEntries);
	}

	/// <summary>
	/// Parses one or more INF files and applies all supported sections to the system
	/// </summary>
	/// <param name="filePaths">Paths to one or more INF files</param>
	/// <exception cref="ArgumentException">Thrown when no file paths are provided</exception>
	/// <exception cref="FileNotFoundException">Thrown when any file doesn't exist</exception>
	/// <exception cref="InvalidOperationException">Thrown when application fails</exception>
	internal static void ParseAndApplyInfFiles(params string[] filePaths)
	{
		Logger.Write($"Starting to parse and apply {filePaths.Length} INF file(s)");

		// Apply System Access policies
		foreach (string filePath in filePaths)
		{
			if (!File.Exists(filePath))
				throw new FileNotFoundException($"INF file not found: {filePath}");

			Logger.Write($"Applying System Access policies from: {filePath}");

			using FileStream fileStream = new(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
			using StreamReader reader = new(fileStream, Encoding.UTF8);
			Dictionary<string, string> settings = SecurityPolicyManager.ExtractSystemAccessSettingsFromReader(reader);

			if (settings.Count > 0)
			{
				ApplySystemAccessSettings(settings);
				Logger.Write("System Access policies applied successfully");
			}
		}

		// Parse all INF files and accumulate their data
		ParsedInfData parsedData = ParseInfFiles(filePaths);

		// Apply Privilege Rights policies
		if (parsedData.PrivilegeRights.Count > 0)
		{
			Logger.Write("Applying Privilege Rights policies...");
			SecurityPolicyWriter.SetPrivilegeRights(parsedData.PrivilegeRights);
			Logger.Write("Privilege Rights policies applied successfully");
		}

		// Apply Registry Policy Entries
		if (parsedData.RegistryPolicyEntries.Count > 0)
		{
			Logger.Write("Applying Registry Policy Entries...");
			RegistryManager.Manager.AddPoliciesToSystem(parsedData.RegistryPolicyEntries);
			Logger.Write("Registry Policy Entries applied successfully");
		}

		Logger.Write("INF files application completed successfully");
	}

	/// <summary>
	/// Helper method to apply System Access settings from a dictionary.
	/// </summary>
	/// <param name="settings"></param>
	/// <exception cref="InvalidOperationException"></exception>
	private static void ApplySystemAccessSettings(Dictionary<string, string> settings)
	{
		if (settings is null || settings.Count == 0)
		{
			return;
		}

		// Collectors for settings that require combined application
		bool hasMinimumPasswordAge = false;
		bool hasMaximumPasswordAge = false;
		int minimumPasswordAge = 0;
		int maximumPasswordAge = 0;

		bool hasLockoutBadCount = false;
		bool hasResetLockoutCount = false;
		bool hasLockoutDuration = false;
		int lockoutBadCount = 0;
		int resetLockoutCount = 0;
		int lockoutDuration = 0;

		// Local parsing helpers
		static int ParseIntStrict(string key, string value)
		{
			if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed))
			{
				throw new InvalidOperationException($"Invalid integer value '{value}' for System Access setting '{key}'.");
			}
			return parsed;
		}

		static string Unquote(string s)
		{
			if (string.IsNullOrEmpty(s))
			{
				return string.Empty;
			}
			if (s.Length >= 2 && s.StartsWith('\"') && s.EndsWith('\"'))
			{
				return s[1..^1];
			}
			return s;
		}

		// Pass 1: parse and apply independent settings, collect combined ones.
		foreach (KeyValuePair<string, string> kv in settings)
		{
			string key = kv.Key;
			string rawValue = kv.Value ?? string.Empty;

			if (string.Equals(key, "MinimumPasswordAge", StringComparison.OrdinalIgnoreCase))
			{
				minimumPasswordAge = ParseIntStrict(key, rawValue);
				hasMinimumPasswordAge = true;
			}
			else if (string.Equals(key, "MaximumPasswordAge", StringComparison.OrdinalIgnoreCase))
			{
				maximumPasswordAge = ParseIntStrict(key, rawValue);
				hasMaximumPasswordAge = true;
			}
			else if (string.Equals(key, "MinimumPasswordLength", StringComparison.OrdinalIgnoreCase))
			{
				int val = ParseIntStrict(key, rawValue);
				SecurityPolicyWriter.SetMinimumPasswordLength(val);
			}
			else if (string.Equals(key, "PasswordComplexity", StringComparison.OrdinalIgnoreCase))
			{
				int val = ParseIntStrict(key, rawValue);
				SecurityPolicyReader.SetPasswordComplexity(val);
			}
			else if (string.Equals(key, "PasswordHistorySize", StringComparison.OrdinalIgnoreCase))
			{
				int val = ParseIntStrict(key, rawValue);
				SecurityPolicyWriter.SetPasswordHistorySize(val);
			}
			else if (string.Equals(key, "LockoutBadCount", StringComparison.OrdinalIgnoreCase))
			{
				lockoutBadCount = ParseIntStrict(key, rawValue);
				hasLockoutBadCount = true;
			}
			else if (string.Equals(key, "ResetLockoutCount", StringComparison.OrdinalIgnoreCase))
			{
				resetLockoutCount = ParseIntStrict(key, rawValue);
				hasResetLockoutCount = true;
			}
			else if (string.Equals(key, "LockoutDuration", StringComparison.OrdinalIgnoreCase))
			{
				lockoutDuration = ParseIntStrict(key, rawValue);
				hasLockoutDuration = true;
			}
			else if (string.Equals(key, "AllowAdministratorLockout", StringComparison.OrdinalIgnoreCase))
			{
				int val = ParseIntStrict(key, rawValue);
				SecurityPolicyReader.SetAllowAdministratorLockout(val);
			}
			else if (string.Equals(key, "RequireLogonToChangePassword", StringComparison.OrdinalIgnoreCase))
			{
				int val = ParseIntStrict(key, rawValue);
				SecurityPolicyReader.SetRequireLogonToChangePassword(val);
			}
			else if (string.Equals(key, "ForceLogoffWhenHourExpire", StringComparison.OrdinalIgnoreCase))
			{
				int val = ParseIntStrict(key, rawValue);
				SecurityPolicyReader.SetForceLogoffWhenHourExpire(val);
			}
			else if (string.Equals(key, "NewAdministratorName", StringComparison.OrdinalIgnoreCase))
			{
				string val = Unquote(rawValue);
				SecurityPolicyReader.SetNewAdministratorName(val);
			}
			else if (string.Equals(key, "NewGuestName", StringComparison.OrdinalIgnoreCase))
			{
				string val = Unquote(rawValue);
				SecurityPolicyReader.SetNewGuestName(val);
			}
			else if (string.Equals(key, "ClearTextPassword", StringComparison.OrdinalIgnoreCase))
			{
				int val = ParseIntStrict(key, rawValue);
				SecurityPolicyReader.SetClearTextPassword(val);
			}
			else if (string.Equals(key, "EnableAdminAccount", StringComparison.OrdinalIgnoreCase))
			{
				int val = ParseIntStrict(key, rawValue);
				SecurityPolicyReader.SetEnableOrDisableAnAccount(SecurityPolicyReader.DOMAIN_USER_RID_ADMIN, val);
			}
			else if (string.Equals(key, "EnableGuestAccount", StringComparison.OrdinalIgnoreCase))
			{
				int val = ParseIntStrict(key, rawValue);
				SecurityPolicyReader.SetEnableOrDisableAnAccount(SecurityPolicyReader.DOMAIN_USER_RID_GUEST, val);
			}
			else if (string.Equals(key, "LSAAnonymousNameLookup", StringComparison.OrdinalIgnoreCase))
			{
				int val = ParseIntStrict(key, rawValue);
				SecurityPolicyReader.LsaAnonymousNameLookupSetValue(val);
			}
			else
			{
				throw new InvalidOperationException($"Unknown System Access setting key: '{key}'.");
			}
		}

		// Pass 2: apply combined settings, preserving existing values for missing counterparts.

		// Minimum/Maximum Password Age
		if (hasMinimumPasswordAge || hasMaximumPasswordAge)
		{
			SystemAccessInfo current = SecurityPolicyReader.GetSystemAccess();
			int finalMin = hasMinimumPasswordAge ? minimumPasswordAge : current.MinimumPasswordAge;
			int finalMax = hasMaximumPasswordAge ? maximumPasswordAge : current.MaximumPasswordAge;

			// Apply: value -1 for MaximumPasswordAge is supported by SetPasswordAge (mapped to FOREVER)
			SecurityPolicyWriter.SetPasswordAge(finalMin, finalMax);
		}

		// Lockout policy (use combined setter when possible, otherwise set individual pieces)
		if (hasLockoutBadCount && hasResetLockoutCount && hasLockoutDuration)
		{
			SecurityPolicyWriter.SetLockoutPolicy(lockoutBadCount, resetLockoutCount, lockoutDuration);
		}
		else
		{
			if (hasLockoutBadCount)
			{
				SecurityPolicyWriter.SetLockoutBadCount(lockoutBadCount);
			}
			if (hasResetLockoutCount)
			{
				SecurityPolicyWriter.SetResetLockoutCount(resetLockoutCount);
			}
			if (hasLockoutDuration)
			{
				SecurityPolicyWriter.SetLockoutDuration(lockoutDuration);
			}
		}
	}

	/// <summary>
	/// Applies one or more POL files to the system with the specified Group Policy context.
	/// </summary>
	/// <param name="context">The Group Policy context (Machine or User) for the POL files</param>
	/// <param name="polFilePaths">Paths to one or more POL files to apply</param>
	/// <exception cref="ArgumentException">Thrown when no file paths are provided</exception>
	internal static void ApplyPolFiles(GroupPolicyContext context, params string[] polFilePaths)
	{
		if (polFilePaths.Length is 0)
			throw new ArgumentException("At least one POL file path must be provided");

		Logger.Write($"Starting to apply {polFilePaths.Length} POL file(s) in {context} context");

		List<RegistryPolicyEntry> accumulatedPolicies = [];

		// Parse each POL file and accumulate entries
		foreach (string polFilePath in polFilePaths)
		{
			Logger.Write($"Parsing POL file: {polFilePath}");

			RegistryPolicyFile policyFile = RegistryPolicyParser.ParseFile(polFilePath);

			Logger.Write($"Loaded {policyFile.Entries.Count} policy entries from {polFilePath}");

			accumulatedPolicies.AddRange(policyFile.Entries);
		}

		Logger.Write($"Total accumulated policies to apply: {accumulatedPolicies.Count}");

		// Apply all accumulated policies to the system with the specified context
		RegistryPolicyParser.AddPoliciesToSystem(accumulatedPolicies, context);

		Logger.Write($"POL files application completed successfully in {context} context");
	}

	#endregion

}
