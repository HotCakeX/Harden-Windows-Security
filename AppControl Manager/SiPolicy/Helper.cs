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
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Text;

namespace AppControlManager.SiPolicy;

internal static class Helper
{

	internal const string DefaultMaxVersion = "65535.65535.65535.65535";

	internal static readonly FrozenDictionary<OptionType, uint> Options = new Dictionary<OptionType, uint>
	{
		{ OptionType.EnabledUMCI, 4U },
		{ OptionType.EnabledBootMenuProtection, 8U },
		{ OptionType.EnabledIntelligentSecurityGraphAuthorization, 16U  },
		{ OptionType.EnabledInvalidateEAsonReboot, 32U },
		{ OptionType.RequiredWHQL, 128U  },
		{ OptionType.EnabledDeveloperModeDynamicCodeTrust, 256U  },
		{ OptionType.EnabledAllowSupplementalPolicies, 1024U  },
		{ OptionType.DisabledRuntimeFilePathRuleProtection, 2048U  },
		{ OptionType.EnabledRevokedExpiredAsUnsigned, 8192U  },
		{ OptionType.EnabledAuditMode, 65536U  },
		{ OptionType.DisabledFlightSigning, 131072U },
		{ OptionType.EnabledInheritDefaultPolicy, 262144U  },
		{ OptionType.EnabledUnsignedSystemIntegrityPolicy, 524288U },
		{ OptionType.EnabledDynamicCodeSecurity, 1048576U  },
		{ OptionType.RequiredEVSigners, 2097152U  },
		{ OptionType.EnabledBootAuditOnFailure, 4194304U  },
		{ OptionType.EnabledAdvancedBootOptionsMenu, 8388608U  },
		{ OptionType.DisabledScriptEnforcement, 16777216U  },
		{ OptionType.RequiredEnforceStoreApplications, 33554432U  },
		{ OptionType.EnabledSecureSettingPolicy, 67108864U  },
		{ OptionType.EnabledManagedInstaller, 134217728U  },
		{ OptionType.EnabledUpdatePolicyNoReboot, 268435456U  },
		{ OptionType.EnabledConditionalWindowsLockdownPolicy, 536870912U  }
	}.ToFrozenDictionary();

	internal static readonly Dictionary<OptionType, Setting> RuleToSettingMapping = new()
	{
		{
			OptionType.DisabledDefaultWindowsCertificateRemapping,
			new Setting()
			{
				Provider = "Microsoft",
				Key = "PolicySettings",
				ValueName = "DisabledDefaultWindowsCertificateRemappingValueName"
			}
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
	private static int CompareByteArrays(byte[]? x, byte[]? y)
	{
		if (x is null && y is null) return 0;
		if (x is null) return -1;
		if (y is null) return 1;

		// lexicographical compare, then by length
		return x.AsSpan().SequenceCompareTo(y);
	}

	/// <summary>
	/// Compare two file rule objects for ordering.
	/// </summary>
	internal static int CompareFileRuleObjects(object x, object y)
	{
		static (int RuleType,
				string FileName,
				string InternalName,
				string FileDescription,
				string ProductName,
				string PackageFamilyName,
				string FilePath,
				byte[] Hash) DeconstructRule(object o) => o switch
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
	internal static object AdaptGenericFileRule(FileRule rule)
	{
		return rule.Type switch
		{
			RuleTypeType.Match => new Allow()
			{
				ID = rule.ID,
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
			RuleTypeType.Exclude => new Deny()
			{
				ID = rule.ID,
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
			RuleTypeType.Attribute => new FileAttrib()
			{
				ID = rule.ID,
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
	}

	/// <summary>
	/// Returns a Setting object for the default policy for AppId Tagging.
	/// </summary>
	internal static Setting CreateDefaultPolicySettingForAppIdTagging()
	{
		return new Setting
		{
			Provider = "WDACAppId",
			Key = "TaggingSettings",
			ValueName = "DefaultPolicy",
			Value = new SettingValueType { Item = true }
		};
	}

	/// <summary>
	/// Converts AppIDTags into a list of secure Settings.
	/// </summary>
	internal static List<Setting> MapAppIdTagsToSecureSettings(AppIDTags Tags)
	{
		List<Setting> secureSettings = [];
		if (Tags.EnforceDLLSpecified && Tags.EnforceDLL)
		{
			Setting setting = new()
			{
				Provider = "WDACAppId",
				Key = "TaggingSettings",
				ValueName = "EnforceDLL",
				Value = new SettingValueType()
			};
			setting.Value.Item = Tags.EnforceDLL;
			secureSettings.Add(setting);
		}
		foreach (AppIDTag appIdTag in Tags.AppIDTag)
		{
			Setting setting = new()
			{
				Provider = "WDACAppId",
				Key = "Tagging",
				ValueName = appIdTag.Key,
				Value = new SettingValueType()
			};
			setting.Value.Item = appIdTag.Value;
			secureSettings.Add(setting);
		}
		return secureSettings;
	}

	/// <summary>
	/// Converts a Signer object to a CiSigner object.
	/// </summary>
	internal static CiSigner ProjectSignerToCiSigner(Signer signer) => new() { SignerId = signer.ID };

	/// <summary>
	/// Converts a version string of up to four "."-separated numeric segments
	/// into a single 64-bit integer by packing each segment into 16 bits.
	/// Returns 0 if <paramref name="version"/> is null.
	/// Throws InvalidOperationException if there are more than four segments,
	/// or FormatException/OverflowException if any segment is not a valid UInt16.
	/// </summary>
	internal unsafe static ulong ConvertStringVersionToUInt64(string? version)
	{
		// If the caller passed null, there is nothing to parse → version 0.0.0.0
		if (version is null)
			return 0UL;

		// We only support up to four segments: major.minor.build.revision
		const int MaxSegments = 4;

		// This will hold the final 64-bit packed result
		ulong result = 0UL;

		// How many valid segments we've successfully parsed so far
		int segmentsParsed = 0;

		// Pin the string's character buffer in memory so we can use unmanaged pointers safely
		fixed (char* pStart = version)
		{
			// Compute the end pointer (one past the last character)
			char* end = pStart + version.Length;

			//
			// First pass: count non‐empty segments to detect “> MaxSegments” early
			//
			int segmentCount = 0;
			char* p = pStart;
			while (p < end)
			{
				// Skip any '.' characters between segments
				while (p < end && *p == '.')
					p++;

				// If we consumed trailing dots, break out
				if (p >= end)
					break;

				// Found the start of a segment
				segmentCount++;

				// Advance until the next dot (or end)
				while (p < end && *p != '.')
					p++;
			}

			// Too many segments → malformed version
			if (segmentCount > MaxSegments)
				throw new InvalidOperationException(string.Format(GlobalVars.GetStr("MalformedVersionDetected"), version));

			//
			// Second pass: extract, parse, and pack each segment into 'result'
			//
			char* ptr = pStart;
			while (ptr < end)
			{
				// Skip leading dots
				while (ptr < end && *ptr == '.')
					ptr++;

				// No more characters → done
				if (ptr >= end)
					break;

				// If we already parsed MaxSegments, any extra data is an error
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
				string part = new(partStart, 0, len);

				// Parse as unsigned 16‐bit integer using invariant culture (no signs, no hex)
				if (!ushort.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out ushort segment))
				{
					// Parsing failed (non‐numeric / overflow) → invalid format
					throw new InvalidOperationException(string.Format(GlobalVars.GetStr("StringFormatIncorrect"), part));
				}

				// Determine how many bits this segment occupies in the 64-bit result:
				// Segment 0 (major) → shift 48 bits; segment 1 → shift 32; segment 2 → shift 16; segment 3 → shift 0.
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
		int scenarioCount = siPolicy.SigningScenarios.Length;

		for (int i = 0; i < scenarioCount; i++)
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

		foreach (RuleType rule in Policy.Rules)
		{
			if (rule.Item is OptionType key
				&& !RuleToSettingMapping.ContainsKey(key)
				&& Options.TryGetValue(key, out uint value))
			{
				flags |= value;
			}
		}

		return flags;
	}

	/// <summary>
	/// Adds settings which are mapped from rules in the policy to the provided SettingsList.
	/// </summary>
	internal static void AppendSettingFromRule(List<Setting> SettingsList, SiPolicy Policy)
	{
		foreach (RuleType rule in Policy.Rules)
		{
			if (rule.Item is OptionType option && RuleToSettingMapping.TryGetValue(option, out Setting? setting))
			{
				setting.Value = new SettingValueType
				{
					Item = true
				};

				SettingsList.Add(setting);
			}
		}
	}

	/// <summary>
	/// Loads and parses an application manifest from a URI (file or web).
	/// </summary>
	internal static AppManifest RetrieveApplicationManifest(HttpClient c, Uri Manifest)
	{
		string content;

		if (Manifest.Scheme == Uri.UriSchemeFile)
		{
			content = File.ReadAllText(Manifest.AbsolutePath);
		}
		else if (Manifest.Scheme == Uri.UriSchemeHttp || Manifest.Scheme == Uri.UriSchemeHttps)
		{
			content = c.GetStringAsync(Manifest).GetAwaiter().GetResult();
		}
		else
		{
			throw new InvalidOperationException(string.Format(GlobalVars.GetStr("InvalidUrlDetectedForAppManifest"), Manifest.Scheme));
		}

		using MemoryStream xmlStream = new(Encoding.UTF8.GetBytes(content));

		return CustomAppManifestLogics.DeserializeAppManifest(null, xmlStream);
	}

}
