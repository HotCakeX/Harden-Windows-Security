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
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AppControlManager.Others;

/// <summary>
/// Represents a policy with various attributes.
/// </summary>
internal sealed class CiPolicyInfo(
	string? policyID,
	string? basePolicyID,
	string? friendlyName,
	Version? version,
	string? versionString,
	bool isSystemPolicy,
	bool isSignedPolicy,
	bool isOnDisk,
	bool isEnforced,
	bool isAuthorized,
	List<string>? policyOptions
)
{
	/// <summary>
	/// Unique identifier for the policy.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("policyID")]
	internal string? PolicyID { get; } = policyID;

	/// <summary>
	/// Identifier for the base policy.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("basePolicyID")]
	internal string? BasePolicyID { get; } = basePolicyID;

	/// <summary>
	/// Human-readable name of the policy.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("friendlyName")]
	internal string? FriendlyName { get; } = friendlyName;

	/// <summary>
	/// Version object representing the policy version.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("version")]
	internal Version? Version { get; } = version;

	/// <summary>
	/// Original version string from the policy data.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("versionString")]
	internal string? VersionString { get; } = versionString;

	/// <summary>
	/// Indicates if it's a system policy.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("isSystemPolicy")]
	internal bool IsSystemPolicy { get; } = isSystemPolicy;

	/// <summary>
	/// Indicates if the policy is signed.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("isSignedPolicy")]
	internal bool IsSignedPolicy { get; } = isSignedPolicy;

	/// <summary>
	/// Indicates if the policy is present on disk.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("isOnDisk")]
	internal bool IsOnDisk { get; } = isOnDisk;

	/// <summary>
	/// Indicates if the policy is enforced.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("isEnforced")]
	internal bool IsEnforced { get; } = isEnforced;

	/// <summary>
	/// Indicates if the policy is authorized.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("isAuthorized")]
	internal bool IsAuthorized { get; } = isAuthorized;

	/// <summary>
	/// List of options or settings related to the policy.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("policyOptions")]
	internal List<string>? PolicyOptions { get; set; } = policyOptions;

	/// <summary>
	/// Gets a comma-separated string representation of the policy options.
	/// </summary>
	[JsonIgnore]
	internal string PolicyOptionsDisplay => PolicyOptions is not null ? string.Join(", ", PolicyOptions) : string.Empty;

	/// <summary>
	/// Intune Configuration policy ID
	/// </summary>
	[JsonIgnore]
	internal string? IntunePolicyObjectID { get; set; }

	/// <summary>
	/// Serializes the given <see cref="CiPolicyInfo"/> instance to a JSON string using source-generated JSON.
	/// </summary>
	/// <param name="policy">The policy instance to serialize.</param>
	/// <returns>A JSON string representation of the policy.</returns>
	internal static string ToJson(CiPolicyInfo policy)
	{
		return JsonSerializer.Serialize(policy, CiPolicyInfoJsonContext.Default.CiPolicyInfo);
	}

	/// <summary>
	/// Deserializes a JSON string into a <see cref="CiPolicyInfo"/> instance using source-generated JSON.
	/// </summary>
	/// <param name="json">The JSON string to deserialize.</param>
	/// <returns>A <see cref="CiPolicyInfo"/> instance, or null if deserialization fails.</returns>
	internal static (bool, CiPolicyInfo?) FromJson(string? json)
	{
		if (json is null)
		{
			return (false, null);
		}

		CiPolicyInfo? result;
		try
		{
			result = JsonSerializer.Deserialize(json, CiPolicyInfoJsonContext.Default.CiPolicyInfo);
		}
		catch
		{
			return (false, null);
		}

		return (true, result);
	}

	/// <summary>
	/// Determines whether the specified object is equal to the current object.
	/// Two <see cref="CiPolicyInfo"/> instances are considered equal if each non-null property is equal.
	/// String comparisons are done using ordinal ignore case.
	/// </summary>
	/// <param name="obj">The object to compare with the current object.</param>
	/// <returns><c>true</c> if the specified object is equal to the current object; otherwise, <c>false</c>.</returns>
	public override bool Equals(object? obj)
	{
		if (obj is not CiPolicyInfo other)
			return false;

		return CompareStrings(PolicyID, other.PolicyID) &&
			   CompareStrings(BasePolicyID, other.BasePolicyID) &&
			   CompareStrings(FriendlyName, other.FriendlyName) &&
			   Equals(Version, other.Version) &&
			   CompareStrings(VersionString, other.VersionString) &&
			   IsSystemPolicy == other.IsSystemPolicy &&
			   IsSignedPolicy == other.IsSignedPolicy &&
			   IsOnDisk == other.IsOnDisk &&
			   IsEnforced == other.IsEnforced &&
			   IsAuthorized == other.IsAuthorized &&
			   CompareStringLists(PolicyOptions, other.PolicyOptions);
	}

	/// <summary>
	/// Serves as the default hash function.
	/// </summary>
	/// <returns>A hash code for the current object.</returns>
	public override int GetHashCode()
	{
		unchecked // Allow arithmetic overflow without exception (standard for hash code generation)
		{
			int hash = 17;
			hash = hash * 23 + (PolicyID is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(PolicyID));
			hash = hash * 23 + (BasePolicyID is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(BasePolicyID));
			hash = hash * 23 + (FriendlyName is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(FriendlyName));
			hash = hash * 23 + (Version is null ? 0 : Version.GetHashCode());
			hash = hash * 23 + (VersionString is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(VersionString));
			hash = hash * 23 + IsSystemPolicy.GetHashCode();
			hash = hash * 23 + IsSignedPolicy.GetHashCode();
			hash = hash * 23 + IsOnDisk.GetHashCode();
			hash = hash * 23 + IsEnforced.GetHashCode();
			hash = hash * 23 + IsAuthorized.GetHashCode();
			if (PolicyOptions != null)
			{
				foreach (string option in PolicyOptions)
				{
					hash = hash * 23 + (option is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(option));
				}
			}
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
	/// Compares two lists of strings for equality.
	/// Two lists are equal if both are null, or if they have the same count and each corresponding element is equal using ordinal ignore case.
	/// </summary>
	/// <param name="list1">First list.</param>
	/// <param name="list2">Second list.</param>
	/// <returns><c>true</c> if the lists are equal, <c>false</c> otherwise.</returns>
	private static bool CompareStringLists(List<string>? list1, List<string>? list2)
	{
		if (list1 is null && list2 is null)
			return true;
		if (list1 is null || list2 is null)
			return false;
		if (list1.Count != list2.Count)
			return false;
		for (int i = 0; i < list1.Count; i++)
		{
			if (!string.Equals(list1[i], list2[i], StringComparison.OrdinalIgnoreCase))
				return false;
		}
		return true;
	}
}

/// <summary>
/// Json serialization context for <see cref="CiPolicyInfo"/> type.
/// </summary>
[JsonSourceGenerationOptions(WriteIndented = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(Others.CiPolicyInfo))]
internal sealed partial class CiPolicyInfoJsonContext : JsonSerializerContext
{
}
