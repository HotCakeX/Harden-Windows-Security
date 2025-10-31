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

using System.Collections.Generic;
using System.IO;
using System.Xml;

namespace HardenSystemSecurity.GroupPolicy;

internal static class AdmxAdmlParser
{
	/// <summary>
	/// Windows PolicyDefinitions root
	/// </summary>
	private static readonly string PolicyDefinitionsPath = Path.Combine(
		Environment.GetFolderPath(Environment.SpecialFolder.Windows),
		"PolicyDefinitions");

	/// <summary>
	/// en-US resource folder
	/// </summary>
	private static readonly string EnUsPath = Path.Combine(PolicyDefinitionsPath, "en-US");

	/// <summary>
	/// Parse ADML/ADMX (en-US only) once per call and fill missing FriendlyName values in-place.
	/// </summary>
	/// <param name="entries"></param>
	internal static void PopulateFriendlyNames(IReadOnlyCollection<RegistryPolicyEntry> entries)
	{
		if (entries == null || entries.Count == 0)
		{
			return; // Nothing to do
		}

		// Collect only entries that actually need resolution to avoid unnecessary parsing work
		HashSet<string> neededCompositeKeys = new(StringComparer.OrdinalIgnoreCase);
		HashSet<string> neededKeyOnly = new(StringComparer.OrdinalIgnoreCase);

		foreach (RegistryPolicyEntry entry in entries)
		{
			if (!string.IsNullOrWhiteSpace(entry.FriendlyName))
			{
				continue; // Already has a friendly name
			}

			string normalizedKey = NormalizeRegistryKey(entry.KeyName);
			if (normalizedKey.Length == 0)
			{
				continue; // Invalid / unusable key
			}

			string valueName = string.IsNullOrWhiteSpace(entry.ValueName) ? string.Empty : entry.ValueName.Trim();

			if (valueName.Length == 0)
			{
				_ = neededKeyOnly.Add(normalizedKey); // Track key-only lookup
			}

			string composite = ComposeCompositeKey(normalizedKey, valueName);
			_ = neededCompositeKeys.Add(composite); // Track key+value lookup
		}

		if (neededCompositeKeys.Count == 0 && neededKeyOnly.Count == 0)
		{
			return; // No entries need resolving
		}

		// Load string resources first, then build lookup dictionaries from ADMX definitions
		Dictionary<string, string> stringResources = ParseEnUsAdmlResources();
		BuildAdmxLookup(stringResources, out Dictionary<string, string> policyIndex, out Dictionary<string, string> keyOnlyIndex);

		// Apply resolved names to the original entries
		foreach (RegistryPolicyEntry entry in entries)
		{
			if (!string.IsNullOrWhiteSpace(entry.FriendlyName))
			{
				continue; // Skip those already resolved (race-safe if reused)
			}

			string normalizedKey = NormalizeRegistryKey(entry.KeyName);
			if (normalizedKey.Length == 0)
			{
				continue;
			}

			string valueName = string.IsNullOrWhiteSpace(entry.ValueName) ? string.Empty : entry.ValueName.Trim();
			string composite = ComposeCompositeKey(normalizedKey, valueName);

			// First try exact key+value
			if (policyIndex.TryGetValue(composite, out string? friendly))
			{
				entry.FriendlyName = friendly;
				continue;
			}

			// If value name is empty attempt key-only
			if (valueName.Length == 0 && keyOnlyIndex.TryGetValue(normalizedKey, out string? keyOnlyFriendly))
			{
				entry.FriendlyName = keyOnlyFriendly;
			}
		}
	}

	// Parse all en-US ADML string resources (id -> localized text)
	private static Dictionary<string, string> ParseEnUsAdmlResources()
	{
		Dictionary<string, string> stringResources = new(StringComparer.OrdinalIgnoreCase);

		if (!Directory.Exists(EnUsPath))
		{
			return stringResources; // No resources folder
		}

		string[] admlFiles;
		try
		{
			admlFiles = Directory.GetFiles(EnUsPath, "*.adml", SearchOption.TopDirectoryOnly);
		}
		catch (Exception ex)
		{
			Logger.Write("Error enumerating en-US ADML files: " + ex.Message);
			return stringResources;
		}

		XmlReaderSettings settings = new()
		{
			DtdProcessing = DtdProcessing.Prohibit,
			IgnoreComments = true,
			IgnoreWhitespace = true,
			CloseInput = true
		};

		for (int i = 0; i < admlFiles.Length; i++)
		{
			string file = admlFiles[i];
			try
			{
				using FileStream fs = new(file, FileMode.Open, FileAccess.Read, FileShare.Read, 8192);
				using XmlReader reader = XmlReader.Create(fs, settings);

				while (reader.Read())
				{
					if (reader.NodeType == XmlNodeType.Element &&
						string.Equals(reader.LocalName, "string", StringComparison.OrdinalIgnoreCase))
					{
						string? id = reader.GetAttribute("id");
						if (string.IsNullOrWhiteSpace(id))
						{
							continue;
						}

						string value = reader.ReadInnerXml().Trim();
						if (value.Length == 0)
						{
							continue;
						}

						stringResources[id] = value; // Last write wins (rare duplicate)
					}
				}
			}
			catch (Exception ex)
			{
				Logger.Write("Failed parsing ADML file " + file + ": " + ex.Message);
			}
		}

		return stringResources;
	}

	// Build lookup dictionaries from all ADMX policies (key|value -> friendly) and (key -> friendly) for key-only
	private static void BuildAdmxLookup(
		Dictionary<string, string> stringResources,
		out Dictionary<string, string> policyIndex,
		out Dictionary<string, string> keyOnlyIndex)
	{
		policyIndex = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		keyOnlyIndex = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

		if (!Directory.Exists(PolicyDefinitionsPath))
		{
			return; // Nothing to parse
		}

		string[] admxFiles;
		try
		{
			admxFiles = Directory.GetFiles(PolicyDefinitionsPath, "*.admx", SearchOption.TopDirectoryOnly);
		}
		catch (Exception ex)
		{
			Logger.Write("Error enumerating ADMX files: " + ex.Message);
			return;
		}

		XmlReaderSettings settings = new()
		{
			DtdProcessing = DtdProcessing.Prohibit,
			IgnoreComments = true,
			IgnoreWhitespace = true,
			CloseInput = true
		};

		for (int i = 0; i < admxFiles.Length; i++)
		{
			string filePath = admxFiles[i];
			try
			{
				using FileStream fs = new(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 8192);
				using XmlReader reader = XmlReader.Create(fs, settings);

				while (reader.Read())
				{
					if (reader.NodeType == XmlNodeType.Element &&
						string.Equals(reader.LocalName, "policy", StringComparison.OrdinalIgnoreCase))
					{
						ProcessPolicyElement(reader, stringResources, policyIndex, keyOnlyIndex);
					}
				}
			}
			catch (Exception ex)
			{
				Logger.Write("Failed parsing ADMX file " + filePath + ": " + ex.Message);
			}
		}
	}

	// Process one <policy> definition and index any value names it defines
	private static void ProcessPolicyElement(
		XmlReader reader,
		Dictionary<string, string> stringResources,
		Dictionary<string, string> policyIndex,
		Dictionary<string, string> keyOnlyIndex)
	{
		string? name = reader.GetAttribute("name");
		if (string.IsNullOrWhiteSpace(name))
		{
			return; // Invalid policy
		}

		string displayNameAttr = reader.GetAttribute("displayName") ?? string.Empty;
		string keyAttr = reader.GetAttribute("key") ?? string.Empty;
		string valueNameAttr = reader.GetAttribute("valueName") ?? string.Empty;

		string resolvedDisplayName = ResolveString(displayNameAttr, stringResources);

		List<string> elementValueNames = new(); // Collect descendant valueName attributes

		using XmlReader subtree = reader.ReadSubtree();
		try
		{
			while (subtree.Read())
			{
				if (subtree.NodeType == XmlNodeType.Element)
				{
					string? elementValueName = subtree.GetAttribute("valueName");
					if (!string.IsNullOrWhiteSpace(elementValueName))
					{
						bool exists = false;
						for (int i = 0; i < elementValueNames.Count; i++)
						{
							if (string.Equals(elementValueNames[i], elementValueName, StringComparison.OrdinalIgnoreCase))
							{
								exists = true;
								break;
							}
						}
						if (!exists)
						{
							elementValueNames.Add(elementValueName);
						}
					}
				}
			}
		}
		catch (Exception ex)
		{
			Logger.Write("Subtree parse error (policy " + name + "): " + ex.Message);
		}

		string normalizedKey = NormalizeRegistryKey(keyAttr);
		if (normalizedKey.Length == 0)
		{
			return; // No indexable path
		}

		string friendly = !string.IsNullOrWhiteSpace(resolvedDisplayName) &&
						  !resolvedDisplayName.StartsWith("$(string.", StringComparison.OrdinalIgnoreCase)
			? resolvedDisplayName
			: name; // Fallback to internal name

		if (!string.IsNullOrWhiteSpace(valueNameAttr))
		{
			AddPolicyIndexEntry(policyIndex, normalizedKey, valueNameAttr, friendly);
		}
		else
		{
			if (!keyOnlyIndex.ContainsKey(normalizedKey))
			{
				keyOnlyIndex[normalizedKey] = friendly;
			}
		}

		for (int i = 0; i < elementValueNames.Count; i++)
		{
			string evn = elementValueNames[i];
			if (!string.IsNullOrWhiteSpace(evn))
			{
				AddPolicyIndexEntry(policyIndex, normalizedKey, evn, friendly);
			}
		}
	}

	// Add a composite (key|value) entry if not present
	private static void AddPolicyIndexEntry(
		Dictionary<string, string> policyIndex,
		string normalizedKey,
		string valueName,
		string friendly)
	{
		string composite = ComposeCompositeKey(normalizedKey, valueName);
		if (!policyIndex.ContainsKey(composite))
		{
			policyIndex[composite] = friendly;
		}
	}

	// Resolve $(string.id) patterns
	private static string ResolveString(string attributeValue, Dictionary<string, string> resources)
	{
		if (string.IsNullOrWhiteSpace(attributeValue))
		{
			return attributeValue;
		}

		if (attributeValue.StartsWith("$(string.", StringComparison.OrdinalIgnoreCase) &&
			attributeValue.EndsWith(')'))
		{
			string id = attributeValue[9..^1];
			if (resources.TryGetValue(id, out string? resolved))
			{
				return resolved;
			}
		}

		return attributeValue;
	}

	// Normalize registry key: remove hive, unify slashes, lowercase
	private static string NormalizeRegistryKey(string keyPath)
	{
		if (string.IsNullOrWhiteSpace(keyPath))
		{
			return string.Empty;
		}

		string normalized = keyPath.Replace('/', '\\').Trim();

		string[] hivePrefixes =
		[
			"HKEY_LOCAL_MACHINE\\",
			"HKLM\\",
			"HKEY_CURRENT_USER\\",
			"HKCU\\",
			"MACHINE\\",
			"USER\\"
		];

		for (int i = 0; i < hivePrefixes.Length; i++)
		{
			string prefix = hivePrefixes[i];
			if (normalized.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
			{
				normalized = normalized[prefix.Length..];
				break;
			}
		}

		normalized = normalized.TrimStart('\\');

		return normalized.ToLowerInvariant();
	}

	// Build composite key used in dictionaries
	private static string ComposeCompositeKey(string normalizedKey, string valueName)
	{
		string vn = string.IsNullOrWhiteSpace(valueName) ? string.Empty : valueName.Trim();
		return normalizedKey + "|" + vn.ToLowerInvariant();
	}
}
