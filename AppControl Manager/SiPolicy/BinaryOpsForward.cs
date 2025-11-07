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
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;

namespace AppControlManager.SiPolicy;

internal static partial class BinaryOpsForward
{
	private static BinaryWriter BodyWriter = null!;
	private static BinaryWriter HeaderWriter = null!;

	[GeneratedRegex(@"\$\(([^()]+)\)", RegexOptions.CultureInvariant | RegexOptions.IgnorePatternWhitespace)]
	private static partial Regex MacroRegex();

	/// <summary>
	/// Writes a string value to the binary writer, with a trailing zero terminator.
	/// </summary>
	internal static void WriteOptionalStringValue(string? value)
	{
		const uint Terminator = 0;

		// if we have no actual text, write a zero-length prefix
		if (string.IsNullOrWhiteSpace(value))
		{
			BodyWriter.Write(Terminator);
		}
		else
		{
			WriteString(value);
		}

		// and in every case, emit the trailing zero terminator
		BodyWriter.Write(Terminator);
	}

	internal static void WriteString(string stringToWrite)
	{
		byte[] utf16Bytes = Encoding.Unicode.GetBytes(stringToWrite);
		uint length = (uint)utf16Bytes.Length;

		BodyWriter.Write(length);

		BodyWriter.Write(utf16Bytes);

		int pad = (int)(-length & 3);
		if (pad > 0)
		{
			Span<byte> padding = stackalloc byte[3];
			padding.Clear();
			BodyWriter.Write(padding[..pad]);
		}
	}

	/// <summary>
	/// Writes a counted array of bytes, padded to next 4-byte boundary.
	/// </summary>
	internal static void WritePaddedCountedBytes(byte[]? data)
	{
		uint length = (uint)(data?.Length ?? 0);
		BodyWriter.Write(length);
		if (length == 0)
		{
			return;
		}

		// write the actual data
		BodyWriter.Write(data!);

		// compute padding
		int padding = -(int)length & 3;
		if (padding > 0)
		{
			BodyWriter.Write(stackalloc byte[padding]);
		}
	}

	/// <summary>
	/// Writes a file rule as binary (for main file rules block).
	/// </summary>
	internal static void ConvertFileRuleToBinary(
		ref Dictionary<string, uint> fileRuleIdToIndexMap,
		object fileRule,
		uint fileRuleIndex)
	{
		switch (fileRule)
		{
			case Allow allowRule:
				fileRuleIdToIndexMap.Add(allowRule.ID, fileRuleIndex);
				BodyWriter.Write(1U);
				WriteOptionalStringValue(allowRule.FileName);
				{
					ulong minFileVersionNumber = Helper.ConvertStringVersionToUInt64(allowRule.MinimumFileVersion);
					BodyWriter.Write((uint)(minFileVersionNumber & uint.MaxValue));
					BodyWriter.Write((uint)(minFileVersionNumber >> 32));
				}
				WritePaddedCountedBytes(allowRule.Hash);
				break;

			case Deny denyRule:
				fileRuleIdToIndexMap.Add(denyRule.ID, fileRuleIndex);
				BodyWriter.Write(0U);
				WriteOptionalStringValue(denyRule.FileName);
				{
					ulong minFileVersionNumber = (denyRule.MinimumFileVersion is not null || denyRule.MaximumFileVersion is not null)
						? Helper.ConvertStringVersionToUInt64(denyRule.MinimumFileVersion)
						: Helper.ConvertStringVersionToUInt64(Helper.DefaultMaxVersion);

					BodyWriter.Write((uint)(minFileVersionNumber & uint.MaxValue));
					BodyWriter.Write((uint)(minFileVersionNumber >> 32));
				}
				WritePaddedCountedBytes(denyRule.Hash);
				break;

			case FileAttrib fileAttributeRule:
				fileRuleIdToIndexMap.Add(fileAttributeRule.ID, fileRuleIndex);
				BodyWriter.Write(2U);
				WriteOptionalStringValue(fileAttributeRule.FileName);
				{
					ulong minFileVersionNumber = Helper.ConvertStringVersionToUInt64(fileAttributeRule.MinimumFileVersion);
					BodyWriter.Write((uint)(minFileVersionNumber & uint.MaxValue));
					BodyWriter.Write((uint)(minFileVersionNumber >> 32));
				}

				WritePaddedCountedBytes(fileAttributeRule.Hash);
				break;

			default:
				throw new InvalidOperationException(GlobalVars.GetStr("FileRuleHasInvalidTypeMessage"));
		}
	}

	/// <summary>
	/// Writes a string or macro value (for AppIDs) to the binary writer.
	/// </summary>
	internal static void ParseStringMacros(
	string strs,
	ref Dictionary<string, string> mapMacroId2Value)
	{
		if (strs is null)
		{
			BodyWriter.Write(0U);
			return;
		}

		if (strs.StartsWith('$'))
		{
			// Split by macro pattern, capturing the macro IDs in the result
			string[] tokens = MacroRegex().Split(strs);
			int length = tokens.Length;

			// Allocate array for replacements without zero-initializing
			string[] replacements = GC.AllocateUninitializedArray<string>(length);

			uint count = 0;

			foreach (string? token in tokens)
			{
				if (!string.IsNullOrEmpty(token))
				{
					if (!mapMacroId2Value.TryGetValue(token, out string? value))
						throw new InvalidOperationException(
							string.Format(
								GlobalVars.GetStr("MacroNotDefinedMessage"),
								token,
								strs));

					replacements[count++] = value;
				}
			}

			if (count == 0)
				throw new InvalidOperationException(
					string.Format(
						GlobalVars.GetStr("NoMacroFoundMessage"),
						strs));

			BodyWriter.Write(count);
			for (uint i = 0; i < count; i++)
				WriteOptionalStringValue(replacements[i]);
		}
		else
		{
			// Single literal string
			BodyWriter.Write(1U);
			WriteOptionalStringValue(strs);
		}
	}

	/// <summary>
	/// Writes AppIDs and MaximumFileVersion for file rules (AppIDs block).
	/// </summary>
	internal static void WriteAppIdsAndMaxFileVersion(
		ref Dictionary<string, string> macroIdToValueMap,
		object fileRule)
	{
		switch (fileRule)
		{
			case Allow allowRule:
				{
					ulong maxFileVersionNumber = 0;
					if (allowRule.MaximumFileVersion is not null)
					{
						maxFileVersionNumber = Helper.ConvertStringVersionToUInt64(allowRule.MaximumFileVersion);
					}

					BodyWriter.Write((uint)(maxFileVersionNumber & uint.MaxValue));

					BodyWriter.Write((uint)(maxFileVersionNumber >> 32));

					ParseStringMacros(allowRule.AppIDs, ref macroIdToValueMap);
				}
				break;

			case Deny denyRule:
				{
					ulong maxFileVersionNumber = 0;
					if (denyRule.MaximumFileVersion is not null)
					{
						maxFileVersionNumber = Helper.ConvertStringVersionToUInt64(denyRule.MaximumFileVersion);
					}

					BodyWriter.Write((uint)(maxFileVersionNumber & uint.MaxValue));
					BodyWriter.Write((uint)(maxFileVersionNumber >> 32));

					ParseStringMacros(denyRule.AppIDs, ref macroIdToValueMap);
				}
				break;

			case FileAttrib fileAttributeRule:
				{
					ulong maxFileVersionNumber = 0;
					if (fileAttributeRule.MaximumFileVersion is not null)
					{
						maxFileVersionNumber = Helper.ConvertStringVersionToUInt64(fileAttributeRule.MaximumFileVersion);
					}

					BodyWriter.Write((uint)(maxFileVersionNumber & uint.MaxValue));
					BodyWriter.Write((uint)(maxFileVersionNumber >> 32));

					ParseStringMacros(fileAttributeRule.AppIDs, ref macroIdToValueMap);
				}
				break;

			default:
				throw new InvalidOperationException(GlobalVars.GetStr("FileRuleHasInvalidTypeMessage"));
		}
	}

	/// <summary>
	/// Writes InternalName, FileDescription, ProductName for file rules.
	/// </summary>
	internal static void WriteFileMetadata(object rule)
	{
		switch (rule)
		{
			case Allow allow:
				WriteOptionalStringValue(allow.InternalName);
				WriteOptionalStringValue(allow.FileDescription);
				WriteOptionalStringValue(allow.ProductName);
				break;

			case Deny deny:
				WriteOptionalStringValue(deny.InternalName);
				WriteOptionalStringValue(deny.FileDescription);
				WriteOptionalStringValue(deny.ProductName);
				break;

			case FileAttrib fileAttrib:
				WriteOptionalStringValue(fileAttrib.InternalName);
				WriteOptionalStringValue(fileAttrib.FileDescription);
				WriteOptionalStringValue(fileAttrib.ProductName);
				break;

			default:
				throw new InvalidOperationException(GlobalVars.GetStr("FileRuleHasInvalidTypeMessage"));
		}
	}

	/// <summary>
	/// Writes PackageFamilyName and PackageVersion for file rules.
	/// </summary>
	internal static void WritePackageInfo(object fileRule)
	{
		switch (fileRule)
		{
			case Allow allowRule:
				{
					WriteOptionalStringValue(allowRule.PackageFamilyName);
					ulong versionNumber = Helper.ConvertStringVersionToUInt64(allowRule.PackageVersion);

					BodyWriter.Write((uint)(versionNumber & uint.MaxValue));
					BodyWriter.Write((uint)(versionNumber >> 32));
				}
				break;

			case Deny denyRule:
				{
					WriteOptionalStringValue(denyRule.PackageFamilyName);
					ulong versionNumber = Helper.ConvertStringVersionToUInt64(denyRule.PackageVersion);

					BodyWriter.Write((uint)(versionNumber & uint.MaxValue));
					BodyWriter.Write((uint)(versionNumber >> 32));
				}
				break;

			case FileAttrib fileAttribRule:
				{
					WriteOptionalStringValue(fileAttribRule.PackageFamilyName);
					ulong versionNumber = Helper.ConvertStringVersionToUInt64(fileAttribRule.PackageVersion);

					BodyWriter.Write((uint)(versionNumber & uint.MaxValue));
					BodyWriter.Write((uint)(versionNumber >> 32));
				}
				break;

			default:
				throw new InvalidOperationException(GlobalVars.GetStr("FileRuleHasInvalidTypeMessage"));
		}
	}

	/// <summary>
	/// Writes FilePath for file rules.
	/// </summary>
	internal static void WriteFilePath(object rule)
	{
		switch (rule)
		{
			case Allow allow:
				WriteOptionalStringValue(allow.FilePath);
				break;

			case Deny deny:
				WriteOptionalStringValue(deny.FilePath);
				break;

			case FileAttrib fileAttrib:
				WriteOptionalStringValue(fileAttrib.FilePath);
				break;

			default:
				throw new InvalidOperationException(GlobalVars.GetStr("FileRuleHasInvalidTypeMessage"));
		}
	}

	/// <summary>
	/// Serializes a Signer into binary format.
	/// </summary>
	internal static void ConvertSignerToBinary(
	Signer signerData,
	Dictionary<string, uint> ekuIdToIndexMap,
	Dictionary<string, uint> fileRuleIdToIndexMap,
	object[]? fileRuleArray)
	{
		ArgumentNullException.ThrowIfNull(fileRuleArray);

		uint tbsCertIndicator = 0;

		if (signerData.CertRoot.Type is CertEnumType.TBS)
		{
			BodyWriter.Write(tbsCertIndicator);
			WritePaddedCountedBytes(signerData.CertRoot.Value);
		}
		else
		{
			uint publicKeyIndicator = 1;

			BodyWriter.Write(publicKeyIndicator);
			BodyWriter.Write((uint)signerData.CertRoot.Value[0]);
		}

		if (signerData.CertEKU is not null)
		{
			BodyWriter.Write((uint)signerData.CertEKU.Length);

			for (uint certEkuIndex = 0; certEkuIndex < signerData.CertEKU.Length; ++certEkuIndex)
			{
				if (!ekuIdToIndexMap.TryGetValue(signerData.CertEKU[(int)certEkuIndex].ID, out uint foundEkuIndex))
				{
					throw new InvalidOperationException(
						string.Format(
							GlobalVars.GetStr("SignerCertEkuReferenceError"),
							signerData.ID,
							signerData.CertEKU[(int)certEkuIndex].ID));
				}
				BodyWriter.Write(foundEkuIndex);
			}
		}
		else
		{
			BodyWriter.Write(0U);
		}

		if (signerData.CertIssuer is not null)
		{
			WriteOptionalStringValue(signerData.CertIssuer.Value);
		}
		else
		{
			WriteOptionalStringValue(null);
		}

		if (signerData.CertPublisher is not null)
		{
			WriteOptionalStringValue(signerData.CertPublisher.Value);
		}
		else
		{
			WriteOptionalStringValue(null);
		}

		if (signerData.CertOemID is not null)
		{
			WriteOptionalStringValue(signerData.CertOemID.Value);
		}
		else
		{
			WriteOptionalStringValue(null);
		}

		if (signerData.FileAttribRef is not null)
		{
			BodyWriter.Write((uint)signerData.FileAttribRef.Length);

			for (uint fileAttribRefIndex = 0; fileAttribRefIndex < signerData.FileAttribRef.Length; ++fileAttribRefIndex)
			{
				if (!fileRuleIdToIndexMap.TryGetValue(signerData.FileAttribRef[(int)fileAttribRefIndex].RuleID, out uint foundFileRuleIndex))
				{
					throw new InvalidOperationException(
						string.Format(
							GlobalVars.GetStr("SignerFileAttribRefNotFoundError"),
							signerData.ID,
							signerData.FileAttribRef[(int)fileAttribRefIndex].RuleID));
				}

				if (fileRuleArray[(int)foundFileRuleIndex] is not FileAttrib)
				{
					throw new InvalidOperationException(
						string.Format(
							GlobalVars.GetStr("FileAttribRefTypeInvalidError"),
							signerData.FileAttribRef[(int)fileAttribRefIndex].RuleID));
				}

				BodyWriter.Write(foundFileRuleIndex);
			}
		}
		else
		{
			BodyWriter.Write(0U);
		}
	}

	/// <summary>
	/// Serializes a SigningScenario to binary.
	/// </summary>
	internal static void ConvertScenarioToBinary(
		SigningScenario signingScenario,
		Dictionary<string, uint> scenarioIdToIndexMap)
	{
		uint scenarioValue = signingScenario.Value;
		BodyWriter.Write(scenarioValue);

		if (signingScenario.InheritedScenarios is not null)
		{
			string[] splittedInheritedScenarios = signingScenario
				.InheritedScenarios
				.Split([",", signingScenario.ID], StringSplitOptions.RemoveEmptyEntries);

			BodyWriter.Write((uint)splittedInheritedScenarios.Length);

			foreach (string scenarioKey in splittedInheritedScenarios)
			{
				if (!scenarioIdToIndexMap.TryGetValue(scenarioKey, out uint foundScenarioIndex))
				{
					throw new InvalidOperationException(
						$"Encountered a SigningScenario with the ID {signingScenario.ID} which inherits an invalid signing scenario: {scenarioKey}."
					);
				}
				BodyWriter.Write(foundScenarioIndex);
			}
		}
		else
		{
			BodyWriter.Write(0U);
		}

		if (signingScenario.MinimumHashAlgorithm != 0)
		{
			BodyWriter.Write((uint)signingScenario.MinimumHashAlgorithm);
		}
		else
		{
			BodyWriter.Write(32780U);
		}
	}

	/// <summary>
	/// Serializes AllowedSigners to binary.
	/// </summary>
	internal static void ConvertAllowedSignersToBinary(
	AllowedSigners? allowedSigners,
	Dictionary<string, uint> signerIdToIndexMap,
	Dictionary<string, uint> fileRuleIdToIndexMap,
	object[]? fileRuleArray)
	{
		ArgumentNullException.ThrowIfNull(fileRuleArray);

		if (allowedSigners is null || allowedSigners.AllowedSigner is null)
		{
			BodyWriter.Write(0U);
			return;
		}

		BodyWriter.Write((uint)allowedSigners.AllowedSigner.Length);
		for (uint signerIndex = 0; signerIndex < allowedSigners.AllowedSigner.Length; ++signerIndex)
		{
			AllowedSigner signer = allowedSigners.AllowedSigner[(int)signerIndex];
			if (!signerIdToIndexMap.TryGetValue(signer.SignerId, out uint foundSignerIndex))
			{
				throw new InvalidOperationException(
					string.Format(
						GlobalVars.GetStr("AllowedSignersSignerIdNotFoundMessage"),
						signer.SignerId,
						signerIndex));
			}

			BodyWriter.Write(foundSignerIndex);

			if (signer.ExceptDenyRule is not null)
			{
				BodyWriter.Write((uint)signer.ExceptDenyRule.Length);

				for (uint denyRuleCounter = 0; denyRuleCounter < signer.ExceptDenyRule.Length; ++denyRuleCounter)
				{
					ExceptDenyRule exceptionRule = signer.ExceptDenyRule[(int)denyRuleCounter];
					if (!fileRuleIdToIndexMap.TryGetValue(exceptionRule.DenyRuleID, out uint foundDenyRuleIndex))
					{
						throw new InvalidOperationException(
							string.Format(
								GlobalVars.GetStr("AllowedSignersDenyRuleNotFoundMessage"),
								exceptionRule.DenyRuleID,
								signer.SignerId,
								denyRuleCounter));
					}

					if (fileRuleArray[(int)foundDenyRuleIndex] is not Deny)
					{
						throw new InvalidOperationException(
							string.Format(
								GlobalVars.GetStr("AllowedSignersExceptDenyRuleTypeInvalidMessage"),
								foundDenyRuleIndex,
								exceptionRule.DenyRuleID));
					}

					BodyWriter.Write(foundDenyRuleIndex);
				}
			}
			else
			{
				BodyWriter.Write(0U);
			}
		}
	}

	/// <summary>
	/// Serializes DeniedSigners to binary.
	/// </summary>
	internal static void ConvertDeniedSignersToBinary(
	DeniedSigners deniedSigners,
	Dictionary<string, uint> signerIdToIndexMap,
	Dictionary<string, uint> fileRuleIdToIndexMap,
	object[]? fileRuleArray)
	{
		ArgumentNullException.ThrowIfNull(fileRuleArray);

		if (deniedSigners is null || deniedSigners.DeniedSigner is null)
		{
			BodyWriter.Write(0U);
			return;
		}

		BodyWriter.Write((uint)deniedSigners.DeniedSigner.Length);
		for (byte signerIndex = 0; signerIndex < deniedSigners.DeniedSigner.Length; ++signerIndex)
		{
			string currentSignerId = deniedSigners.DeniedSigner[signerIndex].SignerId;
			if (!signerIdToIndexMap.TryGetValue(currentSignerId, out uint foundSignerIndex))
				throw new InvalidOperationException(
					string.Format(
						GlobalVars.GetStr("DeniedSignersSignerIdNotFoundMessage"),
						currentSignerId,
						signerIndex));

			BodyWriter.Write(foundSignerIndex);

			ExceptAllowRule[] exceptAllow = deniedSigners.DeniedSigner[signerIndex].ExceptAllowRule;

			if (exceptAllow is not null)
			{
				BodyWriter.Write((uint)exceptAllow.Length);

				for (uint allowRuleIndex = 0; allowRuleIndex < exceptAllow.Length; ++allowRuleIndex)
				{
					string currentAllowRuleId = exceptAllow[(int)allowRuleIndex].AllowRuleID;

					if (!fileRuleIdToIndexMap.TryGetValue(currentAllowRuleId, out uint foundAllowRuleIndex))
					{
						throw new InvalidOperationException(
							string.Format(
								GlobalVars.GetStr("DeniedSignersExceptAllowRuleNotFoundMessage"),
								currentAllowRuleId,
								currentSignerId,
								allowRuleIndex));
					}

					object referencedRule = fileRuleArray[(int)foundAllowRuleIndex];
					if (referencedRule is not Allow)
					{
						string actualType = referencedRule?.GetType().Name ?? "null";
						throw new InvalidOperationException(
							string.Format(
								GlobalVars.GetStr("DeniedSignersExceptAllowRuleTypeInvalidMessage"),
								foundAllowRuleIndex,
								currentAllowRuleId,
								actualType));
					}

					BodyWriter.Write(foundAllowRuleIndex);
				}
			}
			else
			{
				BodyWriter.Write(0U);
			}
		}
	}

	/// <summary>
	/// Serializes secure settings to binary.
	/// </summary>
	internal static void ConvertSecureSettingsToBinary(Setting[] secureSetting)
	{
		if (secureSetting is null)
		{
			BodyWriter.Write(0U);
			return;
		}

		BodyWriter.Write((uint)secureSetting.Length);
		secureSetting.AsSpan().Sort(Helper.CompareSettingObjects);

		for (uint index = 0; index < secureSetting.Length; ++index)
		{
			string key = secureSetting[(int)index].Key;
			string provider = secureSetting[(int)index].Provider;
			string valueName = secureSetting[(int)index].ValueName;

			WriteOptionalStringValue(provider);
			WriteOptionalStringValue(key);
			WriteOptionalStringValue(valueName);

			object data = secureSetting[(int)index].Value.Item;

			if (data is string v2)
			{
				BodyWriter.Write(3U);
				WriteOptionalStringValue(v2);
			}
			else if (data is bool v1)
			{
				BodyWriter.Write(0U);
				BodyWriter.Write((uint)(v1 ? 1 : 0));
			}
			else if (data is uint v)
			{
				BodyWriter.Write(1U);
				BodyWriter.Write(v);
			}
			else // It will be byte
			{
				BodyWriter.Write(2U);
				WritePaddedCountedBytes((byte[])data);
			}
		}
	}

	/// <summary>
	/// Serializes required file rules to binary.
	/// </summary>
	internal static void ConvertRequiredFileRulesToBinary(
		FileRulesRef fileRulesRef,
		Dictionary<string, uint> fileRuleIdToIndexMap)
	{
		if (fileRulesRef is not null && fileRulesRef.FileRuleRef.Length != 0)
		{
			List<uint> fileRuleIndexes = new(fileRulesRef.FileRuleRef.Length);

			BodyWriter.Write((uint)fileRulesRef.FileRuleRef.Length);

			for (uint ruleIndex = 0; ruleIndex < fileRulesRef.FileRuleRef.Length; ++ruleIndex)
			{
				string currentRuleId = fileRulesRef.FileRuleRef[(int)ruleIndex].RuleID;
				if (!fileRuleIdToIndexMap.TryGetValue(currentRuleId, out uint foundFileRuleIndex))
				{
					throw new InvalidOperationException($"Encountered an invalid file rule ID: {currentRuleId}");
				}

				fileRuleIndexes.Add(foundFileRuleIndex);
			}

			fileRuleIndexes.Sort();

			foreach (uint fileRuleIndex in fileRuleIndexes)
			{
				BodyWriter.Write(fileRuleIndex);
			}
		}
		else
		{
			BodyWriter.Write(0U);
		}
	}

	/// <summary>
	/// Writes app settings as binary.
	/// </summary>
	/// <param name="setting"></param>
	internal static void WriteStringSetAppSetting(AppSetting? setting)
	{
		const byte Tag = 4;

		BodyWriter.Write(Tag);

		string[] values = setting switch
		{
			{ Value: string[] arr } => arr,
			null => []
		};

		BodyWriter.Write((uint)values.Length);

		foreach (string rawValue in values)
		{
			WriteOptionalStringValue(rawValue);
		}
	}

	private static void WriteBooleanAppSetting(AppSetting? setting)
	{
		const byte Tag = 0;

		BodyWriter.Write(Tag);

		byte valueByte = setting switch
		{
			null => Tag,
			{ Value: [string rawValue] } => bool.Parse(rawValue) ? (byte)1 : (byte)0,
			_ => throw new InvalidOperationException(
				GlobalVars.GetStr("BoolAppSettingMultipleValuesError"))
		};

		BodyWriter.Write(valueByte);
	}

	internal static void WriteStringAppSetting(AppSetting? setting)
	{
		const byte Tag = 3;

		BodyWriter.Write(Tag);

		string? rawValue = setting switch
		{
			null => null,
			{ Value: [string single] } => single,
			_ => throw new InvalidOperationException(
				GlobalVars.GetStr("StringAppSettingMultipleValuesError"))
		};

		WriteOptionalStringValue(rawValue);
	}

	/// <summary>
	/// Writes application settings region to binary.
	/// </summary>
	internal static void WriteAppSettings(AppSettingRegion appSettingsRegion)
	{
		if (appSettingsRegion is not { App.Length: > 0 })
		{
			BodyWriter.Write(0U);
			return;
		}

		using HttpClient httpClient = new();

		BodyWriter.Write((uint)appSettingsRegion.App.Length);

		foreach (AppRoot appRootItem in appSettingsRegion.App)
		{
			AppManifest applicationManifest = Helper.RetrieveApplicationManifest(httpClient, new Uri(appRootItem.Manifest));

			if (appRootItem.Setting is not null)
			{
				List<AppSetting> missingSettings = appRootItem.Setting.Where(appSetting =>
					!applicationManifest.SettingDefinition
					.Any(def => string.Equals(def.Name, appSetting.Name, StringComparison.OrdinalIgnoreCase)))
					.ToList();

				if (missingSettings.Count > 0)
				{
					string missingDefinitions = string.Join(',', missingSettings.Select(s => s.Name));

					throw new InvalidOperationException(
						string.Format(
							GlobalVars.GetStr("AppSettingsMissingDefinitionsMessage"),
							missingDefinitions));
				}
			}

			WriteOptionalStringValue(applicationManifest.Id);

			BodyWriter.Write((uint)applicationManifest.SettingDefinition.Length);

			foreach (SettingDefinition currentDefinitionInLoop in applicationManifest.SettingDefinition)
			{
				AppSetting? foundSetting = appRootItem.Setting?
					.FirstOrDefault(policySetting =>
						string.Equals(policySetting.Name, currentDefinitionInLoop.Name, StringComparison.OrdinalIgnoreCase));

				WriteOptionalStringValue(currentDefinitionInLoop.Name);

				switch (currentDefinitionInLoop.Type)
				{
					case SettingType.Bool:
						WriteBooleanAppSetting(foundSetting);
						break;
					case SettingType.StringList:
						WriteStringAppSetting(foundSetting);
						break;
					case SettingType.StringSet:
						WriteStringSetAppSetting(foundSetting);
						break;
					default:
						throw new InvalidOperationException(
							string.Format(
								GlobalVars.GetStr("AppSettingsUnknownSettingTypeMessage"),
								currentDefinitionInLoop.Type));
				}

				uint auditFlag = 0;
				if (currentDefinitionInLoop.IgnoreAuditPolicies)
				{
					auditFlag |= 1U;
				}

				BodyWriter.Write(auditFlag);
			}
		}
	}

	internal static void ConvertPolicyToBinary(SiPolicy policyData, Stream outputStream)
	{
		// Create a list to hold secure settings that will be written to the policy body
		List<Setting> secureSettingsList = [];

		// Create a list to hold CI signers projected from Signers when none are provided explicitly
		List<CiSigner> convertedCiSignerList = [];

		// Use Unicode (UTF-16 little endian) encoding without a byte order mark
		UnicodeEncoding encoding = new(false, false);

		// Allocate a memory stream for writing the policy body before prepending header data
		using MemoryStream bodyMemoryStream = new();

		// Initialize writers: BodyWriter writes to the memory stream, HeaderWriter writes to the output stream
		BodyWriter = new(bodyMemoryStream, encoding);
		HeaderWriter = new(outputStream, encoding, true);

		try
		{
			// Determine if this is a supplemental policy
			bool isSupplementalPolicy = policyData.PolicyType is PolicyType.SupplementalPolicy;

			// Prepare dictionaries to map object IDs to their index positions in arrays
			Dictionary<string, uint> ekuIdToIndexMap = [];
			Dictionary<string, uint> fileRuleIdToIndexMap = [];
			Dictionary<string, uint> signerIdToIndexMap = [];
			Dictionary<string, uint> scenarioIdToIndexMap = [];
			Dictionary<string, string> macroIdToValueMap = [];

			// Write a fixed header version (8)
			HeaderWriter.Write(8U);

			// Ensure PolicyTypeID matches BasePolicyID for binary serialization
			policyData.PolicyTypeID = policyData.BasePolicyID;

			// Write the policy type GUID
			Guid policyTypeGuidValue = new(policyData.PolicyTypeID);
			{
				// Get a consistent 16-byte representation on all endians
				ReadOnlySpan<byte> span = policyTypeGuidValue.ToByteArray();
				HeaderWriter.Write(span);
			}

			// Write the platform GUID, or an empty GUID if none specified
			Guid platformGuidValue = !string.IsNullOrEmpty(policyData.PlatformID)
				? new Guid(policyData.PlatformID)
				: new Guid();
			{
				// Get a consistent 16-byte representation on all endians
				ReadOnlySpan<byte> span = platformGuidValue.ToByteArray();
				HeaderWriter.Write(span);
			}

			// Compute base option flags based on policyData properties
			uint policyOptionFlags = Helper.ComputeOptionFlags(policyData);

			// If this is an AppID tagging policy, add default secure setting and specific flags
			if (policyData.PolicyType is PolicyType.AppIDTaggingPolicy)
			{
				secureSettingsList.Add(Helper.CreateDefaultPolicySettingForAppIdTagging());
				policyOptionFlags |= Helper.Options[OptionType.EnabledAuditMode];
				policyOptionFlags |= Helper.Options[OptionType.EnabledUMCI];
				policyOptionFlags |= Helper.Options[OptionType.RequiredEnforceStoreApplications];
				policyOptionFlags |= Helper.Options[OptionType.EnabledAdvancedBootOptionsMenu];
				policyOptionFlags |= Helper.Options[OptionType.DisabledScriptEnforcement];
			}

			// Always set the high-order bit to indicate a signed policy
			policyOptionFlags |= 0x80000000;

			// If supplemental, set the supplemental-policy flag bit
			if (isSupplementalPolicy)
			{
				policyOptionFlags |= 0x40000000;
			}

			// Write the compiled option flags
			HeaderWriter.Write(policyOptionFlags);

			// Write counts of arrays (0 if null)
			HeaderWriter.Write((uint)(policyData.EKUs?.Length ?? 0));
			HeaderWriter.Write((uint)(policyData.FileRules?.Length ?? 0));
			HeaderWriter.Write((uint)(policyData.Signers?.Length ?? 0));
			HeaderWriter.Write((uint)(policyData.SigningScenarios?.Length ?? 0));

			// Collect macros into a lookup for later use in substitutions
			if (policyData.Macros is not null)
			{
				foreach (MacrosMacro macro in policyData.Macros)
				{
					macroIdToValueMap.Add(macro.Id, macro.Value);
				}
			}

			// Convert the string version to a 64-bit number, then split into two 32-bit parts
			ulong parsedVersionNumber = Helper.ConvertStringVersionToUInt64(policyData.VersionEx);
			HeaderWriter.Write((uint)(parsedVersionNumber & uint.MaxValue));    // low 32 bits
			HeaderWriter.Write((uint)(parsedVersionNumber >> 32));              // high 32 bits

			// Reserve space in the header for the body offset (will fill in later)
			int headerPosition = (int)HeaderWriter.BaseStream.Position;
			BodyWriter.Write(0U);

			// Pre-calculate scenario values if scenarios exist
			if (policyData.SigningScenarios is not null)
			{
				uint[] scenarioIndexToValue = new uint[policyData.SigningScenarios.Length];
				Helper.CalculateScenarioValueArray(policyData, ref scenarioIndexToValue);
			}

			// Process each EKU: map its ID to an index, then write its byte value blob
			if (policyData.EKUs is not null)
			{
				for (uint ruleIndex = 0; ruleIndex < policyData.EKUs.Length; ++ruleIndex)
				{
					ekuIdToIndexMap.Add(policyData.EKUs[(int)ruleIndex].ID, ruleIndex);
				}
				foreach (EKU eku in policyData.EKUs)
				{
					WritePaddedCountedBytes(eku.Value);
				}
			}

			// Process file rules: adapt generic rules, sort them, map IDs, then serialize each
			if (policyData.FileRules is not null)
			{
				for (uint ruleIndex = 0; ruleIndex < policyData.FileRules.Length; ++ruleIndex)
				{
					if (policyData.FileRules[(int)ruleIndex] is FileRule genericFileRule)
					{
						policyData.FileRules[(int)ruleIndex] = Helper.AdaptGenericFileRule(genericFileRule);
					}
				}
				policyData.FileRules.AsSpan().Sort(Helper.CompareFileRuleObjects);
				for (uint ruleIndex = 0; ruleIndex < policyData.FileRules.Length; ++ruleIndex)
				{
					ConvertFileRuleToBinary(ref fileRuleIdToIndexMap, policyData.FileRules[(int)ruleIndex], ruleIndex);
				}
			}

			// Map signer IDs to indices for later reference
			if (policyData.Signers is not null)
			{
				for (uint ruleIndex = 0; ruleIndex < policyData.Signers.Length; ++ruleIndex)
				{
					signerIdToIndexMap.Add(policyData.Signers[(int)ruleIndex].ID, ruleIndex);
				}
			}

			// Map scenario IDs to indices
			if (policyData.SigningScenarios is not null)
			{
				for (uint ruleIndex = 0; ruleIndex < policyData.SigningScenarios.Length; ++ruleIndex)
				{
					scenarioIdToIndexMap.Add(policyData.SigningScenarios[(int)ruleIndex].ID, ruleIndex);
				}
			}

			// Serialize each signer, projecting CI signers if needed for AppID policies
			if (policyData.Signers is not null)
			{
				foreach (Signer signer in policyData.Signers)
				{
					ConvertSignerToBinary(signer, ekuIdToIndexMap, fileRuleIdToIndexMap, policyData.FileRules);
					if (policyData.PolicyType is PolicyType.AppIDTaggingPolicy
						&& (policyData.CiSigners is null || policyData.CiSigners.Length == 0))
					{
						convertedCiSignerList.Add(Helper.ProjectSignerToCiSigner(signer));
					}
				}
			}

			// Write UpdatePolicySigners count and each reference, or zero if none
			if (policyData.UpdatePolicySigners is not null && policyData.UpdatePolicySigners.Length != 0)
			{
				BodyWriter.Write((uint)policyData.UpdatePolicySigners.Length);
				foreach (UpdatePolicySigner updateSignerRef in policyData.UpdatePolicySigners)
				{
					if (!signerIdToIndexMap.TryGetValue(updateSignerRef.SignerId, out uint signerIndex))
					{
						throw new InvalidOperationException($"Encountered an invalid signer ID {updateSignerRef.SignerId}.");
					}

					BodyWriter.Write(signerIndex);
				}
			}
			else
			{
				BodyWriter.Write(0U);
			}

			// Write CI signers: explicit list if provided; otherwise use projected list; otherwise zero
			if (policyData.CiSigners is not null && policyData.CiSigners.Length != 0)
			{
				BodyWriter.Write((uint)policyData.CiSigners.Length);
				foreach (CiSigner ciSignerRef in policyData.CiSigners)
				{
					if (!signerIdToIndexMap.TryGetValue(ciSignerRef.SignerId, out uint signerIndex))
					{
						throw new InvalidOperationException($"Encountered an invalid signer ID {ciSignerRef.SignerId}.");
					}

					BodyWriter.Write(signerIndex);
				}
			}
			else if (convertedCiSignerList.Count != 0)
			{
				BodyWriter.Write((uint)convertedCiSignerList.Count);
				foreach (CiSigner ciSigner in convertedCiSignerList)
				{
					if (!signerIdToIndexMap.TryGetValue(ciSigner.SignerId, out uint signerIndex))
					{
						throw new InvalidOperationException($"Encountered an invalid signer ID {ciSigner.SignerId}.");
					}

					BodyWriter.Write(signerIndex);
				}
			}
			else
			{
				BodyWriter.Write(0U);
			}

			// Serialize each signing scenario along with allowed/denied signers and file rules
			if (policyData.SigningScenarios is not null)
			{
				foreach (SigningScenario scenario in policyData.SigningScenarios)
				{
					ConvertScenarioToBinary(scenario, scenarioIdToIndexMap);

					// ProductSigners: allowed, denied, required file rules (or zeros if null)
					if (scenario.ProductSigners is null)
					{
						BodyWriter.Write(0U);
						BodyWriter.Write(0U);
						BodyWriter.Write(0U);
					}
					else
					{
						ConvertAllowedSignersToBinary(scenario.ProductSigners.AllowedSigners, signerIdToIndexMap, fileRuleIdToIndexMap, policyData.FileRules);
						ConvertDeniedSignersToBinary(scenario.ProductSigners.DeniedSigners, signerIdToIndexMap, fileRuleIdToIndexMap, policyData.FileRules);
						ConvertRequiredFileRulesToBinary(scenario.ProductSigners.FileRulesRef, fileRuleIdToIndexMap);
					}

					// TestSigners: allowed, denied, required file rules (or zeros if null)
					if (scenario.TestSigners is null)
					{
						BodyWriter.Write(0U);
						BodyWriter.Write(0U);
						BodyWriter.Write(0U);
					}
					else
					{
						ConvertAllowedSignersToBinary(scenario.TestSigners.AllowedSigners, signerIdToIndexMap, fileRuleIdToIndexMap, policyData.FileRules);
						ConvertDeniedSignersToBinary(scenario.TestSigners.DeniedSigners, signerIdToIndexMap, fileRuleIdToIndexMap, policyData.FileRules);
						ConvertRequiredFileRulesToBinary(scenario.TestSigners.FileRulesRef, fileRuleIdToIndexMap);
					}

					// TestSigningSigners: allowed, denied, required file rules (or zeros if null)
					if (scenario.TestSigningSigners is null)
					{
						BodyWriter.Write(0U);
						BodyWriter.Write(0U);
						BodyWriter.Write(0U);
					}
					else
					{
						ConvertAllowedSignersToBinary(scenario.TestSigningSigners.AllowedSigners, signerIdToIndexMap, fileRuleIdToIndexMap, policyData.FileRules);
						ConvertDeniedSignersToBinary(scenario.TestSigningSigners.DeniedSigners, signerIdToIndexMap, fileRuleIdToIndexMap, policyData.FileRules);
						ConvertRequiredFileRulesToBinary(scenario.TestSigningSigners.FileRulesRef, fileRuleIdToIndexMap);
					}

					// Map AppID tags to secure settings
					if (scenario.AppIDTags is not null)
					{
						secureSettingsList.AddRange(Helper.MapAppIdTagsToSecureSettings(scenario.AppIDTags));
					}
				}
			}

			// Write Hypervisor Code Integrity options flags
			BodyWriter.Write(policyData.HvciOptions);

			// Append explicit policy settings to secureSettingsList
			if (policyData.Settings is not null && policyData.Settings.Length != 0)
			{
				secureSettingsList.AddRange(policyData.Settings);
			}

			// Append settings derived from rules
			Helper.AppendSettingFromRule(secureSettingsList, policyData);

			// Convert all secure settings to binary and write them
			ConvertSecureSettingsToBinary(secureSettingsList.ToArray());

			// Section marker 3: write App IDs and max file version metadata
			BodyWriter.Write(3U);
			if (policyData.FileRules is not null)
			{
				foreach (object fileRule in policyData.FileRules)
				{
					WriteAppIdsAndMaxFileVersion(ref macroIdToValueMap, fileRule);
				}
			}

			// Write signing timestamps (or zero if not set)
			if (policyData.Signers is not null)
			{
				foreach (Signer signer in policyData.Signers)
				{
					if (!signer.SignTimeAfter.Equals(DateTime.MinValue))
					{
						BodyWriter.Write(signer.SignTimeAfter.ToFileTime());
					}
					else
					{
						BodyWriter.Write(0L);
					}
				}
			}

			// Section marker 4: write file metadata for each rule
			BodyWriter.Write(4U);
			if (policyData.FileRules is not null)
			{
				foreach (object fileRule in policyData.FileRules)
				{
					WriteFileMetadata(fileRule);
				}
			}

			// Section marker 5: write package information for each file rule
			BodyWriter.Write(5U);
			if (policyData.FileRules is not null)
			{
				foreach (object fileRule in policyData.FileRules)
				{
					WritePackageInfo(fileRule);
				}
			}

			// Section marker 6: write the policy and base policy GUIDs
			BodyWriter.Write(6U);

			Guid policyIdGuid = new(policyData.PolicyID);
			{
				// Get a consistent 16-byte representation on all endians
				ReadOnlySpan<byte> span = policyIdGuid.ToByteArray();
				BodyWriter.Write(span);
			}

			Guid basePolicyIdGuid = new(policyData.BasePolicyID);
			{
				// Get a consistent 16-byte representation on all endians
				ReadOnlySpan<byte> span = basePolicyIdGuid.ToByteArray();
				BodyWriter.Write(span);
			}

			// Supplemental policy signers: write count and indices or zero if none
			if (policyData.SupplementalPolicySigners is not null && policyData.SupplementalPolicySigners.Length != 0)
			{
				BodyWriter.Write((uint)policyData.SupplementalPolicySigners.Length);
				foreach (SupplementalPolicySigner supSignerRef in policyData.SupplementalPolicySigners)
				{
					if (!signerIdToIndexMap.TryGetValue(supSignerRef.SignerId, out uint signerIndex))
					{
						throw new InvalidOperationException($"Encountered an invalid signer ID {supSignerRef.SignerId}.");
					}

					BodyWriter.Write(signerIndex);
				}
			}
			else
			{
				BodyWriter.Write(0U);
			}

			// Section marker 7: write file paths for each rule
			BodyWriter.Write(7U);
			if (policyData.FileRules is not null)
			{
				foreach (object fileRule in policyData.FileRules)
				{
					WriteFilePath(fileRule);
				}
			}

			// Section marker 8: write application-specific settings
			BodyWriter.Write(8U);
			WriteAppSettings(policyData.AppSettings);

			// Section marker 9: end of sections
			BodyWriter.Write(9U);

			// Calculate and write the size of the body data (excluding the initial size field)
			uint bodyDataSize = (uint)bodyMemoryStream.Position - 4U;
			_ = bodyMemoryStream.Seek(0L, SeekOrigin.Begin);
			BodyWriter.Write(bodyDataSize);

			// Write the body data to the output stream and record its offset
			uint bodyDataOffset = (uint)HeaderWriter.BaseStream.Position;
			bodyMemoryStream.WriteTo(outputStream);

			// Go back and fill in the body offset in the header
			_ = HeaderWriter.BaseStream.Seek(headerPosition, SeekOrigin.Begin);
			HeaderWriter.Write(bodyDataOffset);

			// Move the header stream to its end to finalize the write
			_ = HeaderWriter.BaseStream.Seek(0, SeekOrigin.End);
		}
		finally
		{
			// Ensure all streams and writers are properly closed and disposed
			BodyWriter.Close();
			HeaderWriter.Close();
			BodyWriter.Dispose();
			HeaderWriter.Dispose();
		}
	}

}
