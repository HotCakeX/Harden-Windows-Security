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

using System.Buffers;
using System.Collections.Generic;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CommonCore.Others;

internal sealed class PackagedAppView(
	string displayName,
	string version,
	string packageFamilyName,
	string logo,
	string publisher,
	string architecture,
	string publisherID,
	string fullName,
	string description,
	string installLocation,
	string installedDate,
	object? vmRef = null)
{
	[JsonInclude]
	[JsonPropertyName("Display Name")]
	internal string DisplayName => displayName;

	[JsonInclude]
	[JsonPropertyName("Version")]
	internal string Version => version;

	[JsonInclude]
	[JsonPropertyName("Package Family Name")]
	internal string PackageFamilyName => packageFamilyName;

	[JsonIgnore]
	internal string Logo => logo;

	[JsonInclude]
	[JsonPropertyName("Publisher")]
	internal string Publisher => publisher;

	[JsonInclude]
	[JsonPropertyName("Architecture")]
	internal string Architecture => architecture;

	[JsonInclude]
	[JsonPropertyName("Publisher ID")]
	internal string PublisherID => publisherID;

	[JsonInclude]
	[JsonPropertyName("Full Name")]
	internal string FullName => fullName;

	[JsonInclude]
	[JsonPropertyName("Description")]
	internal string Description => description;

	[JsonInclude]
	[JsonPropertyName("Install Location")]
	internal string InstallLocation => installLocation;

	[JsonInclude]
	[JsonPropertyName("Installed Date")]
	internal string InstalledDate => installedDate;

	[JsonIgnore]
	internal object? VMRef => vmRef;

	/// <summary>
	/// A stable identity for equality and hashing.
	/// </summary>
	[JsonIgnore]
	internal string StableIdentity { get; } = string.Concat(packageFamilyName, "|", architecture);
}

/// <summary>
/// Equality comparer for PackagedAppView that uses <see cref="PackagedAppView.StableIdentity"/>.
/// </summary>
internal sealed class PackagedAppViewIdentityComparer : IEqualityComparer<PackagedAppView>
{
	public bool Equals(PackagedAppView? x, PackagedAppView? y)
	{
		if (ReferenceEquals(x, y)) return true;
		if (x is null || y is null) return false;

		return string.Equals(x.StableIdentity, y.StableIdentity, StringComparison.OrdinalIgnoreCase);
	}

	public int GetHashCode(PackagedAppView? obj)
	{
		if (obj is null) return 0;
		return StringComparer.OrdinalIgnoreCase.GetHashCode(obj.StableIdentity);
	}
}

[JsonSourceGenerationOptions(
	WriteIndented = true,
	PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
	PropertyNameCaseInsensitive = false)]
[JsonSerializable(typeof(PackagedAppView))]
[JsonSerializable(typeof(List<PackagedAppView>))]
internal sealed partial class PackagedAppViewJsonContext : JsonSerializerContext
{
	/// <summary>
	/// Serialize a list of PackagedAppView instances.
	/// Uses Utf8JsonWriter to apply JavaScriptEncoder.UnsafeRelaxedJsonEscaping without mutating the context's Options.
	/// </summary>
	internal static string SerializeList(List<PackagedAppView> units)
	{
		// Use a writer with relaxed escaping and indentation.
		ArrayBufferWriter<byte> buffer = new();
		JsonWriterOptions writerOptions = new()
		{
			Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
			Indented = true
		};
		Utf8JsonWriter writer = new(buffer, writerOptions);

		try
		{
			JsonSerializer.Serialize(writer, units, Default.ListPackagedAppView);
		}
		finally
		{
			writer.Dispose();
		}

		return Encoding.UTF8.GetString(buffer.WrittenSpan);
	}

	/// <summary>
	/// Serialize a single PackagedAppView instance.
	/// </summary>
	internal static string SerializeSingle(PackagedAppView unit)
	{
		ArrayBufferWriter<byte> buffer = new();
		JsonWriterOptions writerOptions = new()
		{
			Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
			Indented = true
		};
		Utf8JsonWriter writer = new(buffer, writerOptions);

		try
		{
			JsonSerializer.Serialize(writer, unit, Default.PackagedAppView);
		}
		finally
		{
			writer.Dispose();
		}

		return Encoding.UTF8.GetString(buffer.WrittenSpan);
	}
}
