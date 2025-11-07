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
	// The origin of this File Identity object, where it came from and how it was compiled
	[JsonInclude]
	internal FileIdentityOrigin Origin { get; init; }

	// Whether the file is signed or unsigned
	[JsonInclude]
	internal SignatureStatus SignatureStatus { get; set; }

	// Properties related to logs
	[JsonInclude]
	internal EventAction Action { get; init; }

	[JsonInclude]
	internal int EventID { get; init; }

	[JsonInclude]
	internal DateTime? TimeCreated { get; init; }

	[JsonInclude]
	internal string? ComputerName { get; init; }

	[JsonInclude]
	internal Guid? PolicyGUID { get; init; }

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
	internal Version? FileVersion { get; set; }

	[JsonInclude]
	internal string? PackageFamilyName { get; set; }

	// Signer and certificate information with a custom comparer to ensure data with the same PublisherTBSHash and IssuerTBSHash do not exist
	[JsonIgnore]
	internal HashSet<FileSignerInfo> FileSignerInfos { get; set; } = new HashSet<FileSignerInfo>(new FileSignerInfoComparer());

	// Just for display purposes, only contains CNs of the signers
	// FileSignerInfos is the one that has actual signing data.
	[JsonIgnore]
	internal HashSet<string> FilePublishers { get; set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

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
			   CompareStrings(ComputerName, other.ComputerName) &&
			   Nullable.Equals(PolicyGUID, other.PolicyGUID) &&
			   Nullable.Equals(UserWriteable, other.UserWriteable) &&
			   CompareStrings(ProcessName, other.ProcessName) &&
			   CompareStrings(RequestedSigningLevel, other.RequestedSigningLevel) &&
			   CompareStrings(ValidatedSigningLevel, other.ValidatedSigningLevel) &&
			   CompareStrings(Status, other.Status) &&
			   Nullable.Equals(USN, other.USN) &&
			   CompareStrings(PolicyName, other.PolicyName) &&
			   CompareStrings(PolicyID, other.PolicyID) &&
			   CompareStrings(PolicyHash, other.PolicyHash) &&
			   CompareStrings(UserID, other.UserID) &&
			   CompareStrings(FilePath, other.FilePath) &&
			   CompareStrings(FileName, other.FileName) &&
			   CompareStrings(SHA1Hash, other.SHA1Hash) &&
			   CompareStrings(SHA256Hash, other.SHA256Hash) &&
			   CompareStrings(SHA1PageHash, other.SHA1PageHash) &&
			   CompareStrings(SHA256PageHash, other.SHA256PageHash) &&
			   CompareStrings(SHA1FlatHash, other.SHA1FlatHash) &&
			   CompareStrings(SHA256FlatHash, other.SHA256FlatHash) &&
			   SISigningScenario == other.SISigningScenario &&
			   CompareStrings(OriginalFileName, other.OriginalFileName) &&
			   CompareStrings(InternalName, other.InternalName) &&
			   CompareStrings(FileDescription, other.FileDescription) &&
			   CompareStrings(ProductName, other.ProductName) &&
			   Equals(FileVersion, other.FileVersion) &&
			   CompareStrings(PackageFamilyName, other.PackageFamilyName) &&
			   CompareHashSets(FileSignerInfos, other.FileSignerInfos) &&
			   CompareStringSets(FilePublishers, other.FilePublishers) &&
			   Nullable.Equals(HasWHQLSigner, other.HasWHQLSigner) &&
			   Nullable.Equals(IsECCSigned, other.IsECCSigned);
	}

	/// <summary>
	/// Serves as the default hash function.
	/// </summary>
	/// <returns>A hash code for the current object.</returns>
	public override int GetHashCode()
	{
		unchecked // Prevents OverflowException on arithmetic overflow, as intended for hash codes
		{
			int hash = 17;
			hash = hash * 23 + Origin.GetHashCode();
			hash = hash * 23 + SignatureStatus.GetHashCode();
			hash = hash * 23 + Action.GetHashCode();
			hash = hash * 23 + EventID.GetHashCode();
			hash = hash * 23 + (TimeCreated?.GetHashCode() ?? 0);
			hash = hash * 23 + (ComputerName is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(ComputerName));
			hash = hash * 23 + (PolicyGUID?.GetHashCode() ?? 0);
			hash = hash * 23 + (UserWriteable?.GetHashCode() ?? 0);
			hash = hash * 23 + (ProcessName is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(ProcessName));
			hash = hash * 23 + (RequestedSigningLevel is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(RequestedSigningLevel));
			hash = hash * 23 + (ValidatedSigningLevel is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(ValidatedSigningLevel));
			hash = hash * 23 + (Status is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(Status));
			hash = hash * 23 + (USN?.GetHashCode() ?? 0);
			hash = hash * 23 + (PolicyName is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(PolicyName));
			hash = hash * 23 + (PolicyID is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(PolicyID));
			hash = hash * 23 + (PolicyHash is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(PolicyHash));
			hash = hash * 23 + (UserID is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(UserID));
			hash = hash * 23 + (FilePath is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(FilePath));
			hash = hash * 23 + (FileName is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(FileName));
			hash = hash * 23 + (SHA1Hash is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(SHA1Hash));
			hash = hash * 23 + (SHA256Hash is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(SHA256Hash));
			hash = hash * 23 + (SHA1PageHash is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(SHA1PageHash));
			hash = hash * 23 + (SHA256PageHash is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(SHA256PageHash));
			hash = hash * 23 + (SHA1FlatHash is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(SHA1FlatHash));
			hash = hash * 23 + (SHA256FlatHash is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(SHA256FlatHash));
			hash = hash * 23 + SISigningScenario.GetHashCode();
			hash = hash * 23 + (OriginalFileName is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(OriginalFileName));
			hash = hash * 23 + (InternalName is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(InternalName));
			hash = hash * 23 + (FileDescription is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(FileDescription));
			hash = hash * 23 + (ProductName is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(ProductName));
			hash = hash * 23 + (FileVersion?.GetHashCode() ?? 0);
			hash = hash * 23 + (PackageFamilyName is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(PackageFamilyName));
			hash = hash * 23 + GetHashCodeForHashSet(FileSignerInfos);
			hash = hash * 23 + GetHashCodeForStringSet(FilePublishers);
			hash = hash * 23 + (HasWHQLSigner?.GetHashCode() ?? 0);
			hash = hash * 23 + (IsECCSigned?.GetHashCode() ?? 0);
			return hash;
		}
	}

	/// <summary>
	/// Compares two strings using ordinal ignore case.
	/// If both strings are null, they are considered equal.
	/// </summary>
	/// <param name="s1">First string.</param>
	/// <param name="s2">Second string.</param>
	/// <returns><c>true</c> if the strings are equal, <c>false</c> otherwise.</returns>
	private static bool CompareStrings(string? s1, string? s2)
	{
		if (s1 is null && s2 is null)
			return true;
		if (s1 is null || s2 is null)
			return false;
		return string.Equals(s1, s2, StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>
	/// Compares two hash sets of FileSignerInfo for equality.
	/// Two sets are considered equal if they contain the same elements.
	/// </summary>
	/// <param name="set1">First hash set.</param>
	/// <param name="set2">Second hash set.</param>
	/// <returns><c>true</c> if the sets are equal, <c>false</c> otherwise.</returns>
	private static bool CompareHashSets(HashSet<FileSignerInfo> set1, HashSet<FileSignerInfo> set2)
	{
		return set1.SetEquals(set2);
	}

	/// <summary>
	/// Compares two hash sets of strings for equality using ordinal ignore case.
	/// Two sets are considered equal if they contain the same elements.
	/// </summary>
	/// <param name="set1">First hash set.</param>
	/// <param name="set2">Second hash set.</param>
	/// <returns><c>true</c> if the sets are equal, <c>false</c> otherwise.</returns>
	private static bool CompareStringSets(HashSet<string> set1, HashSet<string> set2)
	{
		return set1.SetEquals(set2);
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
