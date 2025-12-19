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
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using AppControlManager.SiPolicyIntel;

namespace AppControlManager.IntelGathering;

internal sealed class FileIdentity
{
	#region String representations of Enums for UI display purposes and to avoid calling ToString on actual enum properties when we need the string. Improves performance and lowers allocations. Tested with benchmarks on .NET 10.1
	// Their order mUST match the order of the enum definitions.

	private static readonly string[] SignatureStatusString =
	[
		nameof(SignatureStatus.IsSigned),
		nameof(SignatureStatus.IsUnsigned)
	];
	private static readonly string[] EventActionString =
	[
		nameof(EventAction.Audit),
		nameof(EventAction.Block)
	];

	#endregion

	// The origin of this File Identity object, where it came from and how it was compiled
	[JsonInclude]
	internal FileIdentityOrigin Origin { get; init; }

	// Whether the file is signed or unsigned
	[JsonInclude]
	internal SignatureStatus SignatureStatus { get; set; }

	[JsonIgnore]
	internal string SignatureStatus_String => SignatureStatusString[(int)SignatureStatus];

	// Properties related to logs
	[JsonInclude]
	internal EventAction Action { get; init; }

	[JsonIgnore]
	internal string Action_String => EventActionString[(int)Action];

	[JsonInclude]
	internal int EventID { get; init; }

	[JsonInclude]
	internal DateTime? TimeCreated { get; init; }

	[JsonInclude]
	internal string? ComputerName { get; init; }

	[JsonInclude]
	internal string? PolicyGUID { get; init; }

	[JsonInclude]
	internal bool? UserWriteable { get; init; }

	[JsonInclude]
	internal string? ProcessName { get; init; }

	[JsonInclude]
	internal string? RequestedSigningLevel { get; init; }

	[JsonInclude]
	internal string? ValidatedSigningLevel { get; init; }

	[JsonInclude]
	internal string? Status { get; init; }

	[JsonInclude]
	internal long? USN { get; init; }

	[JsonInclude]
	internal string? PolicyName { get; init; }

	[JsonInclude]
	internal string? PolicyID { get; init; }

	[JsonInclude]
	internal string? PolicyHash { get; init; }

	[JsonInclude]
	internal string? UserID { get; init; }

	// Properties applicable to files in general
	[JsonInclude]
	internal string? FilePath { get; set; }

	[JsonInclude]
	internal string? FileName { get; set; }

	[JsonInclude]
	internal string? SHA1Hash { get; set; } // SHA1 Authenticode Hash with fallback to Flat hash for incompatible files

	[JsonInclude]
	internal string? SHA256Hash { get; set; } // SHA256 Authenticode Hash with fallback to Flat hash for incompatible files

	[JsonInclude]
	internal string? SHA1PageHash { get; set; } // 1st Page hash - Local file scanning provides this

	[JsonInclude]
	internal string? SHA256PageHash { get; set; } // 1st Page hash - Local file scanning provides this

	[JsonInclude]
	internal string? SHA1FlatHash { get; set; } // Flat file hashes - Event logs provide this

	[JsonInclude]
	internal string? SHA256FlatHash { get; set; } // Flat file hashes - Event logs provide this

	[JsonInclude]
	internal SSType SISigningScenario { get; set; }

	[JsonInclude]
	internal string? OriginalFileName { get; set; }

	[JsonInclude]
	internal string? InternalName { get; set; }

	[JsonInclude]
	internal string? FileDescription { get; set; }

	[JsonInclude]
	internal string? ProductName { get; set; }

	[JsonInclude]
	internal Version? FileVersion
	{
		get; set
		{
			field = value;
			FileVersion_String = field?.ToString();
		}
	}

	[JsonIgnore]
	internal string? FileVersion_String { get; private set; }

	[JsonInclude]
	internal string? PackageFamilyName { get; set; }

	// Signer and certificate information with a custom comparer to ensure data with the same PublisherTBSHash and IssuerTBSHash do not exist
	[JsonIgnore]
	internal HashSet<FileSignerInfo> FileSignerInfos { get; set; } = new(new FileSignerInfoComparer());

	// Just for display purposes, only contains CNs of the signers
	// FileSignerInfos is the one that has actual signing data.
	[JsonIgnore]
	internal HashSet<string> FilePublishers { get; set; } = new(StringComparer.OrdinalIgnoreCase);

	// Computed property to join FilePublishers into a comma-separated string
	[JsonInclude]
	internal string FilePublishersToDisplay => string.Join(", ", FilePublishers);

	// If the file has a WHQL signer
	[JsonInclude]
	internal bool? HasWHQLSigner { get; set; }

	// Determines whether the file is signed by ECC algorithm or not
	// AppControl does not support ECC Signed files yet
	[JsonInclude]
	internal bool? IsECCSigned { get; set; }

	// Computed property to gather all OPUSInfo from FileSignerInfos and save them in a comma-separated string for displaying purposes only
	[JsonInclude]
	internal string Opus => string.Join(", ", FileSignerInfos
		.Where(signerInfo => !string.IsNullOrEmpty(signerInfo.OPUSInfo))
		.Select(signerInfo => signerInfo.OPUSInfo));

	/// <summary>
	/// Determines whether the specified object is equal to the current object.
	/// Two <see cref="FileIdentity"/> instances are considered equal if each non-null property (excluding the parent view models and computed properties)
	/// is equal. String comparisons are done using ordinal ignore case.
	/// </summary>
	/// <param name="obj">The object to compare with the current object.</param>
	/// <returns><c>true</c> if the specified object is equal to the current object; otherwise, <c>false</c>.</returns>
	public override bool Equals(object? obj)
	{
		if (obj is not FileIdentity other)
			return false;

		return Origin == other.Origin &&
			   SignatureStatus == other.SignatureStatus &&
			   Action == other.Action &&
			   EventID == other.EventID &&
			   Nullable.Equals(TimeCreated, other.TimeCreated) &&
			   string.Equals(ComputerName, other.ComputerName, StringComparison.OrdinalIgnoreCase) &&
			   string.Equals(PolicyGUID, other.PolicyGUID, StringComparison.OrdinalIgnoreCase) &&
			   Nullable.Equals(UserWriteable, other.UserWriteable) &&
			   string.Equals(ProcessName, other.ProcessName, StringComparison.OrdinalIgnoreCase) &&
			   string.Equals(RequestedSigningLevel, other.RequestedSigningLevel, StringComparison.OrdinalIgnoreCase) &&
			   string.Equals(ValidatedSigningLevel, other.ValidatedSigningLevel, StringComparison.OrdinalIgnoreCase) &&
			   string.Equals(Status, other.Status, StringComparison.OrdinalIgnoreCase) &&
			   Nullable.Equals(USN, other.USN) &&
			   string.Equals(PolicyName, other.PolicyName, StringComparison.OrdinalIgnoreCase) &&
			   string.Equals(PolicyID, other.PolicyID, StringComparison.OrdinalIgnoreCase) &&
			   string.Equals(PolicyHash, other.PolicyHash, StringComparison.OrdinalIgnoreCase) &&
			   string.Equals(UserID, other.UserID, StringComparison.OrdinalIgnoreCase) &&
			   string.Equals(FilePath, other.FilePath, StringComparison.OrdinalIgnoreCase) &&
			   string.Equals(FileName, other.FileName, StringComparison.OrdinalIgnoreCase) &&
			   string.Equals(SHA1Hash, other.SHA1Hash, StringComparison.OrdinalIgnoreCase) &&
			   string.Equals(SHA256Hash, other.SHA256Hash, StringComparison.OrdinalIgnoreCase) &&
			   string.Equals(SHA1PageHash, other.SHA1PageHash, StringComparison.OrdinalIgnoreCase) &&
			   string.Equals(SHA256PageHash, other.SHA256PageHash, StringComparison.OrdinalIgnoreCase) &&
			   string.Equals(SHA1FlatHash, other.SHA1FlatHash, StringComparison.OrdinalIgnoreCase) &&
			   string.Equals(SHA256FlatHash, other.SHA256FlatHash, StringComparison.OrdinalIgnoreCase) &&
			   SISigningScenario == other.SISigningScenario &&
			   string.Equals(OriginalFileName, other.OriginalFileName, StringComparison.OrdinalIgnoreCase) &&
			   string.Equals(InternalName, other.InternalName, StringComparison.OrdinalIgnoreCase) &&
			   string.Equals(FileDescription, other.FileDescription, StringComparison.OrdinalIgnoreCase) &&
			   string.Equals(ProductName, other.ProductName, StringComparison.OrdinalIgnoreCase) &&
			   Equals(FileVersion, other.FileVersion) &&
			   string.Equals(PackageFamilyName, other.PackageFamilyName, StringComparison.OrdinalIgnoreCase) &&
			   FileSignerInfos.SetEquals(other.FileSignerInfos) &&
			   FilePublishers.SetEquals(other.FilePublishers) &&
			   Nullable.Equals(HasWHQLSigner, other.HasWHQLSigner) &&
			   Nullable.Equals(IsECCSigned, other.IsECCSigned);
	}

	/// <summary>
	/// Serves as the default hash function.
	/// </summary>
	/// <returns>A hash code for the current object.</returns>
	public override int GetHashCode()
	{
		HashCode hash = new();
		hash.Add(Origin);
		hash.Add(SignatureStatus);
		hash.Add(Action);
		hash.Add(EventID);
		hash.Add(TimeCreated);
		hash.Add(ComputerName, StringComparer.OrdinalIgnoreCase);
		hash.Add(PolicyGUID);
		hash.Add(UserWriteable);
		hash.Add(ProcessName, StringComparer.OrdinalIgnoreCase);
		hash.Add(RequestedSigningLevel, StringComparer.OrdinalIgnoreCase);
		hash.Add(ValidatedSigningLevel, StringComparer.OrdinalIgnoreCase);
		hash.Add(Status, StringComparer.OrdinalIgnoreCase);
		hash.Add(USN);
		hash.Add(PolicyName, StringComparer.OrdinalIgnoreCase);
		hash.Add(PolicyID, StringComparer.OrdinalIgnoreCase);
		hash.Add(PolicyHash, StringComparer.OrdinalIgnoreCase);
		hash.Add(UserID, StringComparer.OrdinalIgnoreCase);
		hash.Add(FilePath, StringComparer.OrdinalIgnoreCase);
		hash.Add(FileName, StringComparer.OrdinalIgnoreCase);
		hash.Add(SHA1Hash, StringComparer.OrdinalIgnoreCase);
		hash.Add(SHA256Hash, StringComparer.OrdinalIgnoreCase);
		hash.Add(SHA1PageHash, StringComparer.OrdinalIgnoreCase);
		hash.Add(SHA256PageHash, StringComparer.OrdinalIgnoreCase);
		hash.Add(SHA1FlatHash, StringComparer.OrdinalIgnoreCase);
		hash.Add(SHA256FlatHash, StringComparer.OrdinalIgnoreCase);
		hash.Add(SISigningScenario);
		hash.Add(OriginalFileName, StringComparer.OrdinalIgnoreCase);
		hash.Add(InternalName, StringComparer.OrdinalIgnoreCase);
		hash.Add(FileDescription, StringComparer.OrdinalIgnoreCase);
		hash.Add(ProductName, StringComparer.OrdinalIgnoreCase);
		hash.Add(FileVersion);
		hash.Add(PackageFamilyName, StringComparer.OrdinalIgnoreCase);
		hash.Add(GetHashCodeForHashSet(FileSignerInfos));
		hash.Add(GetHashCodeForStringSet(FilePublishers));
		hash.Add(HasWHQLSigner);
		hash.Add(IsECCSigned);
		return hash.ToHashCode();
	}

	/// <summary>
	/// Computes an order-independent hash code for a hash set of FileSignerInfo.
	/// </summary>
	/// <param name="set">The hash set to compute the hash code for.</param>
	/// <returns>The computed hash code.</returns>
	private static int GetHashCodeForHashSet(HashSet<FileSignerInfo> set)
	{
		int hash = 0;
		foreach (FileSignerInfo item in set)
		{
			hash ^= item?.GetHashCode() ?? 0;
		}
		return hash;
	}

	/// <summary>
	/// Computes an order-independent hash code for a hash set of strings using ordinal ignore case.
	/// </summary>
	/// <param name="set">The hash set to compute the hash code for.</param>
	/// <returns>The computed hash code.</returns>
	private static int GetHashCodeForStringSet(HashSet<string> set)
	{
		int hash = 0;
		foreach (string item in set)
		{
			hash ^= item is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(item);
		}
		return hash;
	}

	/// <summary>
	/// Exports the FileIdentities to JSON with UI interaction and state management.
	/// </summary>
	/// <param name="fileIdentities">The collection of FileIdentity objects to export</param>
	/// <param name="infoBarSettings">InfoBar settings for displaying messages</param>
	internal static async Task ExportToJson(
		IEnumerable<FileIdentity> fileIdentities,
		InfoBarSettings infoBarSettings)
	{
		DateTime now = DateTime.Now;
		string formattedDateTime = now.ToString("yyyy-MM-dd_HH-mm-ss");
		string fileName = $"AppControlManager_Data_Export_{formattedDateTime}.json";

		string? savePath = FileDialogHelper.ShowSaveFileDialog(GlobalVars.JSONPickerFilter, fileName);

		if (savePath is null)
			return;

		infoBarSettings.WriteInfo(GlobalVars.GetStr("ExportingToJSONMsg"));

		List<FileIdentity> dataToExport = [];

		await Task.Run(() =>
		{
			dataToExport = fileIdentities.ToList();

			string jsonString = JsonSerializer.Serialize(
				dataToExport,
				FileIdentityJsonSerializationContext.Default.ListFileIdentity);

			File.WriteAllText(savePath, jsonString);
		});

		infoBarSettings.WriteSuccess(string.Format(GlobalVars.GetStr("SuccessfullyExportedDataToJSON"), dataToExport.Count, savePath));
	}
}

/// <summary>
/// JSON source generated context for <see cref="IntelGathering.FileIdentity"/> type.
/// </summary>
[JsonSourceGenerationOptions(
	WriteIndented = true
)]
[JsonSerializable(typeof(FileIdentity))]
[JsonSerializable(typeof(List<FileIdentity>))]
internal sealed partial class FileIdentityJsonSerializationContext : JsonSerializerContext
{
}
