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
using System.Formats.Asn1;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;
using AppControlManager.SiPolicy;

namespace CipPreviewHandler;

/// <summary>
/// Reads the preview facts out of a ".cip" file by delegating the entire header/body binary parse to AppControl
/// Manager's own <see cref="BinaryOpsReverse.ParseSiPolicy"/>.
/// </summary>
internal readonly struct CipPolicyInfo(
		PolicyType policyType,
		string version,
		string signingStatus,
		string policyID,
		string basePolicyID,
		string? policyName,
		string hvci,
		IReadOnlyList<string> ruleOptions,
		uint ekuCount,
		uint fileRuleCount,
		uint signerCount,
		uint scenarioCount)
{
	internal PolicyType PolicyType => policyType;
	internal string Version => version;
	internal string SigningStatus => signingStatus;
	internal string PolicyID => policyID;
	internal string BasePolicyID => basePolicyID;
	internal string? PolicyName => policyName;
	internal string Hvci => hvci;
	internal IReadOnlyList<string> RuleOptions => ruleOptions;
	internal uint EkuCount => ekuCount;
	internal uint FileRuleCount => fileRuleCount;
	internal uint SignerCount => signerCount;
	internal uint ScenarioCount => scenarioCount;

	// The secure setting key that only AppID tagging policies emit
	private const string AppIdTaggingMarker = "TaggingSettings";

	// The Provider and ValueName of the secure setting that carries the policy name.
	private const string PolicyInfoProvider = "PolicyInfo";
	private const string PolicyNameValueName = "Name";

	// The well known content type OID for a signed Code Integrity policy (Secure Boot policy).
	private const string CodeIntegrityOid = "1.3.6.1.4.1.311.79.1";

	/// <summary>
	/// Reads the preview facts from the raw bytes of a ".cip" file.
	/// </summary>
	internal static CipPolicyInfo Read(byte[] fileBytes)
	{
		byte[] payload = ExtractCipContent(fileBytes);

		using MemoryStream memoryStream = new(payload, writable: false);
		using BinaryReader reader = new(memoryStream, Encoding.Unicode, leaveOpen: false);

		SiPolicy policy = BinaryOpsReverse.ParseSiPolicy(reader, static key => key);

		PolicyType policyType = ContainsUtf16(payload, AppIdTaggingMarker) ? PolicyType.AppIDTaggingPolicy : policy.PolicyType;

		bool unsigned = false;
		List<string> ruleOptions = new(policy.Rules.Count);
		foreach (RuleType rule in CollectionsMarshal.AsSpan(policy.Rules))
		{
			if (rule.Item == OptionType.EnabledUnsignedSystemIntegrityPolicy)
				unsigned = true;
			ruleOptions.Add(CustomSerialization.ConvertOptionType(rule.Item));
		}

		string? policyName = null;
		if (policy.Settings is not null)
		{
			foreach (Setting setting in policy.Settings)
			{
				if (setting.Value.Item is string nameValue
					&& string.Equals(setting.Provider, PolicyInfoProvider, StringComparison.OrdinalIgnoreCase)
					&& string.Equals(setting.ValueName, PolicyNameValueName, StringComparison.OrdinalIgnoreCase))
				{
					policyName = nameValue;
					break;
				}
			}
		}

		return new CipPolicyInfo(
			policyType,
			policy.VersionEx,
			unsigned ? "Unsigned" : "Signed",
			NormalizeGuid(policy.PolicyID),
			NormalizeGuid(policy.BasePolicyID),
			policyName,
			HvciLabel(policy.HvciOptions ?? 0),
			ruleOptions,
			(uint)(policy.EKUs?.Count ?? 0),
			(uint)(policy.FileRules?.Count ?? 0),
			(uint)(policy.Signers?.Count ?? 0),
			(uint)(policy.SigningScenarios?.Count ?? 0));
	}

	private static string NormalizeGuid(string value) => Guid.TryParse(value, out Guid guid) ? guid.ToString("B").ToUpperInvariant() : value;

	// Mirrors PolicyEditorVM.GetHVCIOptionKey, with a numeric fallback instead of throwing.
	private static string HvciLabel(uint value) => value switch
	{
		0 => "None",
		1 => "Enabled",
		2 => "Enabled - Strict",
		4 => "Debug Mode",
		8 => "Disable is Allowed",
		_ => value.ToString(CultureInfo.InvariantCulture)
	};

	/// <summary>
	/// Returns the raw CIP payload, unwrapping a PKCS#7 SignedData wrapper if the policy is signed.
	/// </summary>
	private static byte[] ExtractCipContent(byte[] fileBytes)
	{
		SignedCms signedCms = new();
		try
		{
			signedCms.Decode(fileBytes);
		}
		catch (CryptographicException)
		{
			return fileBytes;
		}

		if (!string.Equals(signedCms.ContentInfo.ContentType.Value, CodeIntegrityOid, StringComparison.OrdinalIgnoreCase))
			return fileBytes;

		byte[] content = signedCms.ContentInfo.Content;
		if (content.Length == 0)
			return fileBytes;

		if (content[0] != 0x04)
			return content;

		try
		{
			AsnReader asnReader = new(content, AsnEncodingRules.DER);
			return asnReader.ReadOctetString();
		}
		catch (AsnContentException)
		{
			return content;
		}
	}

	/// <summary>
	/// Scans a byte payload for a UTF-16LE encoded ASCII marker string.
	/// </summary>
	private static bool ContainsUtf16(ReadOnlySpan<byte> payload, string marker)
	{
		int byteLength = marker.Length * 2;
		if (payload.Length < byteLength)
			return false;

		Span<byte> needle = stackalloc byte[byteLength];
		_ = Encoding.Unicode.GetBytes(marker, needle);

		return payload.IndexOf(needle) >= 0;
	}
}
