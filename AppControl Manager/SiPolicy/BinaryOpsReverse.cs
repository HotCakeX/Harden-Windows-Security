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
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;
using System.Xml;

namespace AppControlManager.SiPolicy;

internal static class BinaryOpsReverse
{

	/// <summary>
	/// Entry point to convert a binary .cip file into its XML representation.
	/// Reads, parses, and serializes the policy object.
	/// </summary>
	/// <param name="binaryFilePath">Input CIP file path</param>
	internal static SiPolicy ConvertBinaryToXmlFile(string binaryFilePath)
	{
		byte[] cipContent = ExtractCipContent(binaryFilePath);
		using MemoryStream memoryStream = new(cipContent);
		using BinaryReader reader = new(memoryStream, Encoding.Unicode, leaveOpen: false);

		SiPolicy policy = ParseSiPolicy(reader);

		// PolicyTypeID is not needed in the XML, clear it
		policy.PolicyTypeID = string.Empty;

		// Serialize it it because we need to pass the SiPolicy obj to
		XmlDocument xmlObj = CustomSerialization.CreateXmlFromSiPolicy(policy);

		// Deserialize it because we need to normalize the content such as empty or whitespaces values for File Rules etc.
		// The policy will essentially pass from Serialization and Deserialization, each including many layers of checks for correctness.
		return CustomDeserialization.DeserializeSiPolicy(null, xmlObj);
	}

	private static byte[] ExtractCipContent(string binaryFilePath)
	{
		byte[] fileBytes = File.ReadAllBytes(binaryFilePath);
		try
		{
			// Try to parse as PKCS#7 SignedData
			SignedCms signedCms = new();
			signedCms.Decode(fileBytes);

			Logger.Write(GlobalVars.GetStr("LogCIPFileIsSigned"));

			return signedCms.ContentInfo.Content;
		}
		catch (CryptographicException)
		{
			// Not a signed file, assume it's the raw CIP content
			return fileBytes;
		}
	}

	/// <summary>
	/// Parses the binary .cip file content to reconstruct the SiPolicy C# object.
	/// Handles all versioned blocks and structure.
	/// </summary>
	private static SiPolicy ParseSiPolicy(BinaryReader reader)
	{
		const ulong DefaultMaxVersionNumber = ulong.MaxValue;
		SiPolicy policy = new();

		// HEADER PARSING
		_ = reader.BaseStream.Seek(0, SeekOrigin.Begin);

		// magic/version = which blocks follow
		uint version = reader.ReadUInt32();

		policy.PolicyTypeID = policy.BasePolicyID = new Guid(reader.ReadBytes(16)).ToString();
		policy.PlatformID = new Guid(reader.ReadBytes(16)).ToString("B");
		uint flags = reader.ReadUInt32();

		// Parse Rules from flag bits
		policy.Rules = Helper.Options
			.Where(kvp => (flags & kvp.Value) != 0)
			.Select(kvp => new RuleType { Item = kvp.Key })
			.ToArray();

		// Header counts for later parsing
		uint ekuCount = reader.ReadUInt32();
		uint fileRuleCount = reader.ReadUInt32();
		uint signerCount = reader.ReadUInt32();
		uint scenarioCount = reader.ReadUInt32();

		// Policy version
		ulong verLow = reader.ReadUInt32();
		ulong verHigh = reader.ReadUInt32();
		policy.VersionEx = NumberToStringVersionFixed((verHigh << 32) | verLow);

		// Offset to main data body
		uint bodyOffset = reader.ReadUInt32();
		if (bodyOffset + 4 > reader.BaseStream.Length)
		{
			throw new InvalidOperationException(GlobalVars.GetStr("ErrorBodyOffsetInvalid"));
		}
		_ = reader.BaseStream.Seek(bodyOffset, SeekOrigin.Begin);
		_ = reader.ReadUInt32(); // skip body length

		// EKU SECTION
		List<EKU> ekuList = [];
		for (int i = 0; i < (int)ekuCount; i++)
		{
			byte[] value = ReadCountedAlignedBytes(reader);
			string id = $"ID_EKU_E_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}";
			ekuList.Add(new EKU { ID = id, FriendlyName = string.Empty, Value = value });
		}
		policy.EKUs = ekuList.ToArray();
		string[] ekuIds = ekuList.Select(e => e.ID).ToArray();

		// FILERULES SECTION
		object[] fileRules = new object[fileRuleCount];
		string[] fileRuleIds = new string[fileRuleCount];
		for (uint i = 0; i < fileRuleCount; i++)
		{
			uint type = reader.ReadUInt32();
			string? fn = ReadStringValue(reader);
			uint minL = reader.ReadUInt32();
			uint minH = reader.ReadUInt32();
			ulong minNum = ((ulong)minH << 32) | minL;
			string minVer = (minNum is not DefaultMaxVersionNumber and not 0)
				? NumberToStringVersionFixed(minNum)
				: string.Empty;
			byte[] hash = ReadCountedAlignedBytes(reader);
			string id = type switch
			{
				0 => $"ID_DENY_A_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}",
				1 => $"ID_ALLOW_A_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}",
				2 => $"ID_FILEATTRIB_A_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}",
				_ => $"ID_FILE_A_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}"
			};
			fileRuleIds[i] = id;
			object fr = type switch
			{
				0 => new Deny { ID = id, FileName = fn, MinimumFileVersion = minVer, Hash = hash },
				1 => new Allow { ID = id, FileName = fn, MinimumFileVersion = minVer, Hash = hash },
				2 => new FileAttrib { ID = id, FileName = fn, MinimumFileVersion = minVer, Hash = hash },
				_ => throw new InvalidOperationException(string.Format(GlobalVars.GetStr("ErrorUnknownFileRuleType"), type))
			};
			fileRules[i] = fr;
		}
		policy.FileRules = fileRules;

		// SIGNERS SECTION
		List<Signer> signerList = [];
		string[] signerIds = new string[signerCount];
		for (int idx = 0; idx < signerCount; idx++)
		{
			Signer s = ParseSigner(reader, ekuIds, fileRuleIds);
			string id = $"ID_SIGNER_A_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}";
			s.ID = id;
			signerIds[idx] = id;
			signerList.Add(s);
		}
		policy.Signers = signerList.ToArray();

		// UPDATE POLICY SIGNERS
		uint upCount = reader.ReadUInt32();
		policy.UpdatePolicySigners = Enumerable.Range(0, (int)upCount)
			.Select(_ => new UpdatePolicySigner { SignerId = signerIds[reader.ReadUInt32()] })
			.ToArray();

		// CI SIGNERS
		uint ciCount = reader.ReadUInt32();
		policy.CiSigners = Enumerable.Range(0, (int)ciCount)
			.Select(_ => new CiSigner { SignerId = signerIds[reader.ReadUInt32()] })
			.ToArray();

		// SIGNING SCENARIOS
		List<SigningScenario> scenList = [];
		for (int si = 0; si < scenarioCount; si++)
			scenList.Add(ParseScenario(reader, signerIds, fileRuleIds, si));
		policy.SigningScenarios = scenList.ToArray();

		// HVCI OPTIONS
		policy.HvciOptions = reader.ReadUInt32();
		policy.HvciOptionsSpecified = true;

		// SETTINGS SECTION
		uint setCount = reader.ReadUInt32();
		List<Setting> sets = [];
		for (uint i = 0; i < setCount; i++)
		{
			string? prov = ReadStringValue(reader);
			string? key = ReadStringValue(reader);
			string? valName = ReadStringValue(reader);
			uint t = reader.ReadUInt32();
			object? data = t switch
			{
				0 => reader.ReadUInt32() == 1,
				1 => reader.ReadUInt32(),
				2 => ReadCountedAlignedBytes(reader),
				3 => ReadStringValue(reader),
				_ => throw new InvalidOperationException(string.Format(GlobalVars.GetStr("ErrorUnknownSettingType"), t))
			};
			sets.Add(new Setting { Provider = prov, Key = key, ValueName = valName, Value = new SettingValueType { Item = data } });
		}
		policy.Settings = sets.ToArray();

		// Version‐specific blocks:
		if (version >= 3)
		{
			uint tag3 = reader.ReadUInt32();
			if (tag3 != 3) throw new InvalidOperationException(string.Format(GlobalVars.GetStr("ErrorExpectedV3BlockTagGot"), tag3));
			for (int i = 0; i < fileRuleCount; i++)
			{
				uint maxL = reader.ReadUInt32();
				uint maxH = reader.ReadUInt32();
				ulong maxNum = ((ulong)maxH << 32) | maxL;
				if (maxNum > 0)
				{
					string versionFixed = NumberToStringVersionFixed(maxNum);
					if (fileRules[i] is Deny d) d.MaximumFileVersion = versionFixed;
					else if (fileRules[i] is Allow a) a.MaximumFileVersion = versionFixed;
					else if (fileRules[i] is FileAttrib fa) fa.MaximumFileVersion = versionFixed;
					else if (fileRules[i] is FileRule fr) fr.MaximumFileVersion = versionFixed;
				}

				uint appIdCount = reader.ReadUInt32();
				List<string> appIds = [];
				for (uint j = 0; j < appIdCount; j++)
				{
					string? appId = ReadStringValue(reader);
					if (!string.IsNullOrEmpty(appId))
						appIds.Add(appId);
				}
				if (appIds.Count > 0)
				{
					string combined = string.Join(",", appIds);
					if (fileRules[i] is Deny d2) d2.AppIDs = combined;
					else if (fileRules[i] is Allow a2) a2.AppIDs = combined;
					else if (fileRules[i] is FileAttrib fa2) fa2.AppIDs = combined;
					else if (fileRules[i] is FileRule fr2) fr2.AppIDs = combined;
				}
			}
			foreach (Signer s in policy.Signers)
				ParseSignerV3(reader, s);
		}

		if (version >= 4)
		{
			uint tag4 = reader.ReadUInt32();
			if (tag4 != 4) throw new InvalidOperationException(string.Format(GlobalVars.GetStr("ErrorExpectedV4BlockTagGot"), tag4));
			for (int i = 0; i < fileRuleCount; i++)
			{
				string? internalName = ReadStringValue(reader);
				string? fileDescription = ReadStringValue(reader);
				string? productName = ReadStringValue(reader);
				if (!string.IsNullOrEmpty(internalName))
				{
					if (fileRules[i] is Deny d) d.InternalName = internalName;
					else if (fileRules[i] is Allow a) a.InternalName = internalName;
					else if (fileRules[i] is FileAttrib fa) fa.InternalName = internalName;
					else if (fileRules[i] is FileRule fr) fr.InternalName = internalName;
				}
				if (!string.IsNullOrEmpty(fileDescription))
				{
					if (fileRules[i] is Deny d) d.FileDescription = fileDescription;
					else if (fileRules[i] is Allow a) a.FileDescription = fileDescription;
					else if (fileRules[i] is FileAttrib fa) fa.FileDescription = fileDescription;
					else if (fileRules[i] is FileRule fr) fr.FileDescription = fileDescription;
				}
				if (!string.IsNullOrEmpty(productName))
				{
					if (fileRules[i] is Deny d) d.ProductName = productName;
					else if (fileRules[i] is Allow a) a.ProductName = productName;
					else if (fileRules[i] is FileAttrib fa) fa.ProductName = productName;
					else if (fileRules[i] is FileRule fr) fr.ProductName = productName;
				}
			}
		}

		if (version >= 5)
		{
			uint tag5 = reader.ReadUInt32();
			if (tag5 != 5) throw new InvalidOperationException(string.Format(GlobalVars.GetStr("ErrorExpectedV5BlockTagGot"), tag5));
			for (int i = 0; i < fileRuleCount; i++)
			{
				string? pfn = ReadStringValue(reader);
				uint pkgVerL = reader.ReadUInt32();
				uint pkgVerH = reader.ReadUInt32();
				ulong pkgVerNum = ((ulong)pkgVerH << 32) | pkgVerL;
				if (!string.IsNullOrEmpty(pfn))
				{
					if (fileRules[i] is Deny d) d.PackageFamilyName = pfn;
					else if (fileRules[i] is Allow a) a.PackageFamilyName = pfn;
					else if (fileRules[i] is FileAttrib fa) fa.PackageFamilyName = pfn;
					else if (fileRules[i] is FileRule fr) fr.PackageFamilyName = pfn;
				}
				if (pkgVerNum > 0)
				{
					string ver = NumberToStringVersionFixed(pkgVerNum);
					if (fileRules[i] is Deny d) d.PackageVersion = ver;
					else if (fileRules[i] is Allow a) a.PackageVersion = ver;
					else if (fileRules[i] is FileAttrib fa) fa.PackageVersion = ver;
					else if (fileRules[i] is FileRule fr) fr.PackageVersion = ver;
				}
			}
		}

		if (version >= 6)
		{
			uint tag6 = reader.ReadUInt32();
			if (tag6 != 6) throw new InvalidOperationException(string.Format(GlobalVars.GetStr("ErrorExpectedV6BlockTagGot"), tag6));
			policy.PolicyID = new Guid(reader.ReadBytes(16)).ToString("B").ToUpperInvariant();
			policy.BasePolicyID = new Guid(reader.ReadBytes(16)).ToString("B").ToUpperInvariant();
			policy.PolicyType = (policy.PolicyID == policy.BasePolicyID)
				? PolicyType.BasePolicy
				: PolicyType.SupplementalPolicy;
			policy.PolicyTypeSpecified = true;
			uint supCount = reader.ReadUInt32();
			policy.SupplementalPolicySigners = Enumerable.Range(0, (int)supCount)
				.Select(_ => new SupplementalPolicySigner { SignerId = signerIds[reader.ReadUInt32()] })
				.ToArray();
		}

		if (version >= 7)
		{
			uint tag7 = reader.ReadUInt32();
			if (tag7 != 7) throw new InvalidOperationException(string.Format(GlobalVars.GetStr("ErrorExpectedV7BlockTagGot"), tag7));
			for (int i = 0; i < fileRuleCount; i++)
			{
				string? filePath = ReadStringValue(reader);
				if (!string.IsNullOrEmpty(filePath))
				{
					if (fileRules[i] is Deny d) d.FilePath = filePath;
					else if (fileRules[i] is Allow a) a.FilePath = filePath;
					else if (fileRules[i] is FileAttrib fa) fa.FilePath = filePath;
					else if (fileRules[i] is FileRule fr) fr.FilePath = filePath;
				}
			}
		}

		if (version >= 8)
		{
			uint tag8 = reader.ReadUInt32();
			if (tag8 != 8) throw new InvalidOperationException(string.Format(GlobalVars.GetStr("ErrorExpectedV8BlockTagGot"), tag8));
			policy.AppSettings = ParseAppSettings(reader);
		}

		// End tag: should be version+1
		uint expectedEndTag = version + 1;
		uint endTag = reader.ReadUInt32();
		if (endTag != expectedEndTag)
		{
			throw new InvalidOperationException(string.Format(GlobalVars.GetStr("ErrorExpectedPolicyEndTagGot"), expectedEndTag, endTag));
		}

		return policy;
	}

	/// <summary>
	/// Parse a Signer structure from binary, including EKU and file attribute references.
	/// </summary>
	private static Signer ParseSigner(BinaryReader reader, string[] ekuIds, string[] fileRuleIds)
	{
		Signer signer = new();

		uint ind = reader.ReadUInt32();
		signer.CertRoot = ind == 0
			? new CertRoot { Type = CertEnumType.TBS, Value = ReadCountedAlignedBytes(reader) }
			: new CertRoot { Type = CertEnumType.Wellknown, Value = [(byte)reader.ReadUInt32()] };

		uint ekuRefCount = reader.ReadUInt32();
		signer.CertEKU = new CertEKU[ekuRefCount];
		for (uint j = 0; j < ekuRefCount; j++)
		{
			uint ekuIndex = reader.ReadUInt32();
			if (ekuIndex >= ekuIds.Length)
				throw new InvalidOperationException($"Invalid CertEKU index {ekuIndex}.");
			signer.CertEKU[j] = new CertEKU { ID = ekuIds[ekuIndex] };
		}

		signer.CertIssuer = new CertIssuer { Value = ReadStringValue(reader) };
		signer.CertPublisher = new CertPublisher { Value = ReadStringValue(reader) };
		signer.CertOemID = new CertOemID { Value = ReadStringValue(reader) };

		uint faCount = reader.ReadUInt32();
		signer.FileAttribRef = new FileAttribRef[faCount];
		for (uint j = 0; j < faCount; j++)
		{
			uint ridx = reader.ReadUInt32();
			if (ridx >= fileRuleIds.Length)
				throw new InvalidOperationException($"Invalid FileAttribRef index {ridx}.");
			signer.FileAttribRef[j] = new FileAttribRef { RuleID = fileRuleIds[ridx] };
		}

		signer.Name = string.Empty;
		signer.SignTimeAfter = DateTime.MinValue;
		signer.SignTimeAfterSpecified = false;
		return signer;
	}

	private static void ParseSignerV3(BinaryReader reader, Signer signer)
	{
		long ft = reader.ReadInt64();
		signer.SignTimeAfter = ft != 0 ? DateTime.FromFileTime(ft) : DateTime.MinValue;
		signer.SignTimeAfterSpecified = ft != 0;
	}

	private static SigningScenario ParseScenario(
		BinaryReader reader,
		string[] signerIds,
		string[] fileRuleIds,
		int scenarioIndex)
	{
		SigningScenario scen = new()
		{
			ID = $"ID_SIGNINGSCENARIO_A_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}",
			Value = (byte)reader.ReadUInt32()
		};

		uint inhCount = reader.ReadUInt32();
		List<string> inhList = [];
		for (uint i = 0; i < inhCount; i++)
		{
			uint idx = reader.ReadUInt32();
			string inheritedId = $"ID_SIGNINGSCENARIO_A_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}-{idx}";
			inhList.Add(inheritedId);
		}
		scen.InheritedScenarios = inhCount > 0 ? string.Join(",", inhList) : string.Empty;

		uint minHash = reader.ReadUInt32();
		scen.MinimumHashAlgorithm = (minHash is not 32780U and <= ushort.MaxValue)
			? (ushort)minHash
			: (ushort)0;
		scen.MinimumHashAlgorithmSpecified = minHash != 32780U;

		scen.ProductSigners = new ProductSigners
		{
			AllowedSigners = ParseAllowedSigners(reader, signerIds, fileRuleIds),
			DeniedSigners = ParseDeniedSigners(reader, signerIds, fileRuleIds),
			FileRulesRef = ParseFileRulesRef(reader, fileRuleIds)
		};
		scen.TestSigners = new TestSigners
		{
			AllowedSigners = ParseAllowedSigners(reader, signerIds, fileRuleIds),
			DeniedSigners = ParseDeniedSigners(reader, signerIds, fileRuleIds),
			FileRulesRef = ParseFileRulesRef(reader, fileRuleIds)
		};
		scen.TestSigningSigners = new TestSigningSigners
		{
			AllowedSigners = ParseAllowedSigners(reader, signerIds, fileRuleIds),
			DeniedSigners = ParseDeniedSigners(reader, signerIds, fileRuleIds),
			FileRulesRef = ParseFileRulesRef(reader, fileRuleIds)
		};
		return scen;
	}

	/// <summary>
	/// Parse an AllowedSigners structure from binary.
	/// </summary>
	private static AllowedSigners ParseAllowedSigners(
		BinaryReader reader,
		string[] signerIds,
		string[] fileRuleIds)
	{
		uint c = reader.ReadUInt32();
		AllowedSigner[] arr = new AllowedSigner[c];
		for (uint i = 0; i < c; i++)
		{
			uint sid = reader.ReadUInt32();
			uint exc = reader.ReadUInt32();
			ExceptDenyRule[] exArr = new ExceptDenyRule[exc];
			for (uint j = 0; j < exc; j++)
			{
				uint ridx = reader.ReadUInt32();
				exArr[j] = new ExceptDenyRule { DenyRuleID = fileRuleIds[ridx] };
			}
			arr[i] = new AllowedSigner
			{
				SignerId = signerIds[sid],
				ExceptDenyRule = exArr
			};
		}
		return new AllowedSigners { AllowedSigner = arr };
	}

	/// <summary>
	/// Parse a DeniedSigners structure from binary.
	/// </summary>
	private static DeniedSigners ParseDeniedSigners(
		BinaryReader reader,
		string[] signerIds,
		string[] fileRuleIds)
	{
		uint c = reader.ReadUInt32();
		DeniedSigner[] arr = new DeniedSigner[c];
		for (uint i = 0; i < c; i++)
		{
			uint sid = reader.ReadUInt32();
			uint exc = reader.ReadUInt32();
			ExceptAllowRule[] exArr = new ExceptAllowRule[exc];
			for (uint j = 0; j < exc; j++)
			{
				uint ridx = reader.ReadUInt32();
				exArr[j] = new ExceptAllowRule { AllowRuleID = fileRuleIds[ridx] };
			}
			arr[i] = new DeniedSigner
			{
				SignerId = signerIds[sid],
				ExceptAllowRule = exArr
			};
		}
		return new DeniedSigners { DeniedSigner = arr };
	}

	/// <summary>
	/// Parse a FileRulesRef structure from binary.
	/// </summary>
	private static FileRulesRef ParseFileRulesRef(
		BinaryReader reader,
		string[] fileRuleIds)
	{
		uint c = reader.ReadUInt32();
		FileRuleRef[] arr = new FileRuleRef[c];
		for (uint i = 0; i < c; i++)
		{
			uint ridx = reader.ReadUInt32();
			arr[i] = new FileRuleRef { RuleID = fileRuleIds[ridx] };
		}
		return new FileRulesRef { FileRuleRef = arr };
	}

	/// <summary>
	/// Parse the AppSettings region from the binary policy.
	/// </summary>
	private static AppSettingRegion ParseAppSettings(BinaryReader reader)
	{
		uint c = reader.ReadUInt32();
		AppRoot[] arr = new AppRoot[c];
		for (uint i = 0; i < c; i++)
		{
			string? mid = ReadStringValue(reader);
			uint defCount = reader.ReadUInt32();
			List<AppSetting> settings = [];
			for (uint j = 0; j < defCount; j++)
			{
				string? name = ReadStringValue(reader);
				byte tag = reader.ReadByte();
				string?[] values = tag switch
				{
					0 => [reader.ReadByte() == 1 ? "true" : "false"],
					1 => [reader.ReadByte().ToString(CultureInfo.InvariantCulture)],
					3 => [ReadStringValue(reader)],
					4 => Enumerable.Range(0, (int)reader.ReadUInt32())
						.Select(_ => ReadStringValue(reader))
						.ToArray(),
					_ => throw new InvalidOperationException($"Unknown app setting tag {tag}")
				};
				_ = reader.ReadUInt32(); // audit flag, currently ignored
				settings.Add(new AppSetting { Name = name, Value = values });
			}
			arr[i] = new AppRoot { Manifest = mid, Setting = settings.ToArray() };
		}
		return new AppSettingRegion { App = arr };
	}

	/// <summary>
	/// Reads a length-prefixed and 4-byte aligned Unicode string from the binary reader.
	/// </summary>
	private static string? ReadStringValue(BinaryReader reader)
	{
		uint len = reader.ReadUInt32();
		if (len == 0)
		{
			_ = reader.ReadUInt32();
			return null;
		}
		byte[] buf = reader.ReadBytes((int)len);
		int pad = -(int)len & 3;
		if (pad > 0) _ = reader.ReadBytes(pad);
		_ = reader.ReadUInt32();
		return Encoding.Unicode.GetString(buf);
	}

	/// <summary>
	/// Reads a length-prefixed and 4-byte aligned byte array from the binary reader.
	/// </summary>
	private static byte[] ReadCountedAlignedBytes(BinaryReader reader)
	{
		uint len = reader.ReadUInt32();
		if (len == 0) return [];
		long rem = reader.BaseStream.Length - reader.BaseStream.Position;
		if (len > rem) throw new InvalidOperationException($"Invalid byte-array length {len}");
		byte[] data = reader.ReadBytes((int)len);
		int pad = -(int)len & 3;
		if (pad > 0) _ = reader.ReadBytes(pad);
		return data;
	}

	/// <summary>
	/// Converts a 64-bit version number to a 4-part dot-separated version string.
	/// </summary>
	private unsafe static string NumberToStringVersionFixed(ulong version)
	{
		ushort* p = (ushort*)&version;
		int idx0 = BitConverter.IsLittleEndian ? 3 : 0;
		int idx1 = BitConverter.IsLittleEndian ? 2 : 1;
		int idx2 = BitConverter.IsLittleEndian ? 1 : 2;
		int idx3 = BitConverter.IsLittleEndian ? 0 : 3;
		return $"{p[idx0]}.{p[idx1]}.{p[idx2]}.{p[idx3]}";
	}

}
