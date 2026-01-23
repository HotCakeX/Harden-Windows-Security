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
using System.Runtime.InteropServices;
using System.Text;

namespace AppControlManager.SiPolicy;

internal static class Helper
{
	internal const string DefaultMaxVersion = "65535.65535.65535.65535";

	internal static readonly Dictionary<OptionType, Setting> RuleToSettingMapping = new()
	{
		{
			OptionType.DisabledDefaultWindowsCertificateRemapping,
			new Setting(
				provider: "Microsoft",
				key: "PolicySettings",
				valueName: "DisabledDefaultWindowsCertificateRemappingValueName",
				value: new SettingValueType(item: true)
			)
		}
	};

	/// <summary>
	/// Compare two settings for ordering (Provider, Key, ValueName).
	/// </summary>
	internal static int CompareSettingObjects(object X, object Y)
	{
		Setting settingX = (Setting)X;
		Setting settingY = (Setting)Y;

		// Compare Provider
		int result = string.Compare(
			settingX.Provider,
			settingY.Provider,
			StringComparison.OrdinalIgnoreCase
		);

		if (result == 0)
		{
			// If Providers are equal, compare Key
			result = string.Compare(
				settingX.Key,
				settingY.Key,
				StringComparison.OrdinalIgnoreCase
			);

			if (result == 0)
			{
				// If Keys are also equal, compare ValueName
				result = string.Compare(
					settingX.ValueName,
					settingY.ValueName,
					StringComparison.OrdinalIgnoreCase
				);
			}
		}

		return result;
	}

	/// <summary>
	/// Compare two byte arrays lexicographically, then by length.
	/// </summary>
	private static int CompareByteArrays(ReadOnlyMemory<byte> x, ReadOnlyMemory<byte> y)
	{
		if (x.IsEmpty && y.IsEmpty) return 0;
		if (x.IsEmpty) return -1;
		if (y.IsEmpty) return 1;

		// lexicographical compare, then by length
		return x.Span.SequenceCompareTo(y.Span);
	}

	/// <summary>
	/// Compare two file rule objects for ordering.
	/// </summary>
	internal static int CompareFileRuleObjects(object x, object y)
	{
		static (int RuleType,
				string? FileName,
				string? InternalName,
				string? FileDescription,
				string? ProductName,
				string? PackageFamilyName,
				string? FilePath,
				ReadOnlyMemory<byte> Hash) DeconstructRule(object o) => o switch
				{
					Deny d => (0, d.FileName, d.InternalName, d.FileDescription, d.ProductName, d.PackageFamilyName, d.FilePath, d.Hash),
					Allow a => (1, a.FileName, a.InternalName, a.FileDescription, a.ProductName, a.PackageFamilyName, a.FilePath, a.Hash),
					FileAttrib f => (2, f.FileName, f.InternalName, f.FileDescription, f.ProductName, f.PackageFamilyName, f.FilePath, f.Hash),
					_ => throw new InvalidOperationException(GlobalVars.GetStr("EncounteredInvalidFileRule"))
				};

		var r1 = DeconstructRule(x);
		var r2 = DeconstructRule(y);

		// First by rule type
		int result = r1.RuleType - r2.RuleType;
		if (result != 0)
			return result;

		// Then chain string comparisons, stopping at first non-zero:
		result = string.Compare(r1.FileName, r2.FileName, StringComparison.OrdinalIgnoreCase);
		if (result != 0) return result;

		result = string.Compare(r1.InternalName, r2.InternalName, StringComparison.OrdinalIgnoreCase);
		if (result != 0) return result;

		result = string.Compare(r1.FileDescription, r2.FileDescription, StringComparison.OrdinalIgnoreCase);
		if (result != 0) return result;

		result = string.Compare(r1.ProductName, r2.ProductName, StringComparison.OrdinalIgnoreCase);
		if (result != 0) return result;

		result = string.Compare(r1.PackageFamilyName, r2.PackageFamilyName, StringComparison.OrdinalIgnoreCase);
		if (result != 0) return result;

		result = string.Compare(r1.FilePath, r2.FilePath, StringComparison.OrdinalIgnoreCase);
		if (result != 0) return result;

		// Finally compare the hashes
		return CompareByteArrays(r1.Hash, r2.Hash);
	}

	/// <summary>
	/// Converts a generic FileRule object into a typed file rule (Allow, Deny, FileAttrib).
	/// </summary>
	internal static object AdaptGenericFileRule(FileRule rule) => rule.Type switch
	{
		RuleTypeType.Match => new Allow(id: rule.ID)
		{
			FriendlyName = rule.FriendlyName,
			FileName = rule.FileName,
			InternalName = rule.InternalName,
			FileDescription = rule.FileDescription,
			ProductName = rule.ProductName,
			PackageFamilyName = rule.PackageFamilyName,
			PackageVersion = rule.PackageVersion,
			MinimumFileVersion = rule.MinimumFileVersion,
			MaximumFileVersion = rule.MaximumFileVersion,
			Hash = rule.Hash,
			AppIDs = rule.AppIDs,
			FilePath = rule.FilePath
		},
		RuleTypeType.Exclude => new Deny(id: rule.ID)
		{
			FriendlyName = rule.FriendlyName,
			FileName = rule.FileName,
			InternalName = rule.InternalName,
			FileDescription = rule.FileDescription,
			ProductName = rule.ProductName,
			PackageFamilyName = rule.PackageFamilyName,
			PackageVersion = rule.PackageVersion,
			MinimumFileVersion = rule.MinimumFileVersion,
			MaximumFileVersion = rule.MaximumFileVersion,
			Hash = rule.Hash,
			AppIDs = rule.AppIDs,
			FilePath = rule.FilePath
		},
		RuleTypeType.Attribute => new FileAttrib(id: rule.ID)
		{
			FriendlyName = rule.FriendlyName,
			FileName = rule.FileName,
			InternalName = rule.InternalName,
			FileDescription = rule.FileDescription,
			ProductName = rule.ProductName,
			PackageFamilyName = rule.PackageFamilyName,
			PackageVersion = rule.PackageVersion,
			MinimumFileVersion = rule.MinimumFileVersion,
			MaximumFileVersion = rule.MaximumFileVersion,
			Hash = rule.Hash,
			AppIDs = rule.AppIDs,
			FilePath = rule.FilePath
		},
		_ => throw new InvalidOperationException(GlobalVars.GetStr("EncounteredInvalidFileRule"))
	};

	/// <summary>
	/// Converts AppIDTags into a list of secure Settings.
	/// </summary>
	internal static List<Setting> MapAppIdTagsToSecureSettings(AppIDTags Tags)
	{
		List<Setting> secureSettings = [];
		if (Tags.EnforceDLL == true)
		{
			Setting setting = new(
				provider: "WDACAppId",
				key: "TaggingSettings",
				valueName: "EnforceDLL",
				value: new SettingValueType(item: Tags.EnforceDLL)
			);
			secureSettings.Add(setting);
		}
		foreach (AppIDTag appIdTag in CollectionsMarshal.AsSpan(Tags.AppIDTag))
		{
			Setting setting = new(
				provider: "WDACAppId",
				key: "Tagging",
				valueName: appIdTag.Key,
				value: new SettingValueType(item: appIdTag.Value)
			);
			secureSettings.Add(setting);
		}
		return secureSettings;
	}

	/// <summary>
	/// Converts a version string of up to four "."-separated numeric segments
	/// into a single 64-bit integer by packing each segment into 16 bits.
	/// Returns 0 if <paramref name="version"/> is null.
	/// Throws InvalidOperationException if there are more than four segments,
	/// or FormatException/OverflowException if any segment is not a valid UInt16.
	/// </summary>
	internal unsafe static ulong ConvertStringVersionToUInt64(string? version)
	{
		// If the caller passed null, there is nothing to parse -> version 0.0.0.0
		if (version is null)
			return 0UL;

		// We only support up to four segments: major.minor.build.revision
		const int MaxSegments = 4;

		// This will hold the final 64-bit packed result
		ulong result = 0UL;

		// How many valid segments we've successfully parsed so far
		int segmentsParsed = 0;

		// Pin the string's character buffer in memory so we can use unmanaged pointers safely
		// Get a pointer to the first character in the string
		fixed (char* pStart = version)
		{
			// Compute the end pointer (one past the last character so we can have clean loop below that doesn't require constantly checking "count < length" inside the loop)
			char* end = pStart + version.Length;
			char* ptr = pStart;

			// We iterate through the string once
			while (ptr < end)
			{
				// Skip leading dots
				while (ptr < end && *ptr == '.')
					ptr++;

				// If we hit the end after skipping dots, we are done
				if (ptr >= end)
					break;

				// If we are about to parse a segment but we already found 4,
				// that means this is the 5th segment -> Error.
				if (segmentsParsed >= MaxSegments)
					throw new InvalidOperationException(string.Format(GlobalVars.GetStr("MalformedVersionDetected"), version));

				// Mark the beginning of this segment
				char* partStart = ptr;
				char* partEnd = ptr;

				// Find the end of the segment (next dot or end of string)
				while (partEnd < end && *partEnd != '.')
					partEnd++;

				// Calculate segment length and allocate a temporary string for parsing
				int len = (int)(partEnd - partStart);

				if (len == 0)
				{
					// Empty segment (e.g., "1..2") is invalid
					string part = new(partStart, 0, len);
					throw new InvalidOperationException(string.Format(GlobalVars.GetStr("StringFormatIncorrect"), part));
				}

				uint val = 0;
				char* pDigit = partStart;

				// Parse digits manually without allocating a string
				do
				{
					// Calculate numeric value of digit
					// We cast to uint so that if *pDigit is < '0', the result wraps to a large positive number
					// effectively checking both bounds (>= '0' && <= '9') in a single comparison.
					uint digit = (uint)(*pDigit - '0');

					if (digit > 9)
					{
						// Invalid character encountered
						string part = new(partStart, 0, len);
						throw new InvalidOperationException(string.Format(GlobalVars.GetStr("StringFormatIncorrect"), part));
					}

					val = (val * 10) + digit;

					// Check for overflow (ushort max is 65535)
					if (val > 65535)
					{
						string part = new(partStart, 0, len);
						throw new InvalidOperationException(string.Format(GlobalVars.GetStr("StringFormatIncorrect"), part));
					}

					pDigit++;
				} while (pDigit < partEnd);

				ushort segment = (ushort)val;

				// Determine how many bits this segment occupies in the 64-bit result:
				// Segment 0 (major) -> shift 48 bits; segment 1 -> shift 32; segment 2 -> shift 16; segment 3 -> shift 0.
				int shiftBits = (MaxSegments - 1 - segmentsParsed) * 16;

				// Pack this segment into the result
				result |= (ulong)segment << shiftBits;

				// One more segment successfully parsed
				segmentsParsed++;

				// Advance our pointer to the end of the just‐parsed segment
				ptr = partEnd;
			}
		}

		// Return the fully-packed version number as a ulong
		return result;
	}

	/// <summary>
	/// Populates scenarioIndex2Value with the Value field of each scenario in siPolicy.SigningScenarios.
	/// </summary>
	internal static void CalculateScenarioValueArray(SiPolicy siPolicy, ref uint[] scenarioIndex2Value)
	{
		if (siPolicy.SigningScenarios is null) return;

		for (int i = 0; i < siPolicy.SigningScenarios.Count; i++)
		{
			scenarioIndex2Value[i] = siPolicy.SigningScenarios[i].Value;
		}
	}

	/// <summary>
	/// Computes the policy option flags from the rules in the policy.
	/// </summary>
	internal static uint ComputeOptionFlags(SiPolicy Policy)
	{
		uint flags = 0;

		foreach (RuleType rule in CollectionsMarshal.AsSpan(Policy.Rules))
		{
			if (!RuleToSettingMapping.ContainsKey(rule.Item))
			{
				flags |= (uint)rule.Item;
			}
		}

		return flags;
	}

	/// <summary>
	/// Adds settings which are mapped from rules in the policy to the provided SettingsList.
	/// </summary>
	internal static void AppendSettingFromRule(List<Setting> SettingsList, SiPolicy Policy)
	{
		foreach (RuleType rule in CollectionsMarshal.AsSpan(Policy.Rules))
		{
			if (rule.Item is OptionType option && RuleToSettingMapping.TryGetValue(option, out Setting? setting))
			{
				setting.Value = new SettingValueType
				(
					item: true
				);

				SettingsList.Add(setting);
			}
		}
	}

	/// <summary>
	/// Loads and parses an application manifest from a URI (file or web).
	/// </summary>
	internal static AppManifest RetrieveApplicationManifest(Uri Manifest)
	{
		string content = Manifest.Scheme == Uri.UriSchemeFile
			? File.ReadAllText(Manifest.AbsolutePath)
			: Manifest.Scheme == Uri.UriSchemeHttp || Manifest.Scheme == Uri.UriSchemeHttps
				? SecHttpClient.Instance.GetStringAsync(Manifest).GetAwaiter().GetResult()
				: throw new InvalidOperationException(string.Format(GlobalVars.GetStr("InvalidUrlDetectedForAppManifest"), Manifest.Scheme));

		using MemoryStream xmlStream = new(Encoding.UTF8.GetBytes(content));

		return CustomAppManifestLogics.DeserializeAppManifest(null, xmlStream);
	}

}
