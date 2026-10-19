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
using System.IO;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using AppControlManager.CustomUIElements;
using CommonCore.GroupPolicy;
using HardenSystemSecurity.Protect;
using HardenSystemSecurity.ViewModels;

namespace HardenSystemSecurity.Traverse;

/// <summary>
/// Base type that provides a concrete Score property and a strongly-typed Items list.
/// </summary>
/// <typeparam name="TItem"></typeparam>
internal abstract class CategoryBase<TItem>(List<TItem> items)
{
	/// <summary>
	/// Used only during total score calculation; not serialized.
	/// </summary>
	[JsonIgnore]
	internal int Score { get; init; }

	/// <summary>
	/// Since it's read-only, needs to be public so during deserialization the code will see it and won't try to set it.
	/// </summary>
	[JsonPropertyName("Count")]
	[JsonPropertyOrder(0)]
	public int Count => Items.Count;

	[JsonInclude]
	[JsonPropertyName("Items")]
	[JsonPropertyOrder(1)]
	internal List<TItem> Items => items;
}

// One class per category with the appropriate item list type

internal sealed class MicrosoftSecurityBaseline(List<VerificationResult> items) : CategoryBase<VerificationResult>(items);
internal sealed class Microsoft365AppsSecurityBaseline(List<VerificationResult> items) : CategoryBase<VerificationResult>(items);

internal sealed class AttackSurfaceReductionRules(List<ASRRuleEntry> items) : CategoryBase<ASRRuleEntry>(items);

internal sealed class OptionalWindowsFeatures(List<DISMOutputEntry> items) : CategoryBase<DISMOutputEntry>(items);

// MUnit based
internal sealed class MicrosoftDefender(List<MUnit> items) : CategoryBase<MUnit>(items);
internal sealed class BitLockerSettings(List<MUnit> items) : CategoryBase<MUnit>(items);
internal sealed class TLSSecurity(List<MUnit> items) : CategoryBase<MUnit>(items);
internal sealed class LockScreen(List<MUnit> items) : CategoryBase<MUnit>(items);
internal sealed class UserAccountControl(List<MUnit> items) : CategoryBase<MUnit>(items);
internal sealed class DeviceGuard(List<MUnit> items) : CategoryBase<MUnit>(items);
internal sealed class WindowsFirewall(List<MUnit> items) : CategoryBase<MUnit>(items);
internal sealed class WindowsNetworking(List<MUnit> items) : CategoryBase<MUnit>(items);
internal sealed class MiscellaneousConfigurations(List<MUnit> items) : CategoryBase<MUnit>(items);
internal sealed class WindowsUpdateConfigurations(List<MUnit> items) : CategoryBase<MUnit>(items);
internal sealed class EdgeBrowserConfigurations(List<MUnit> items) : CategoryBase<MUnit>(items);
internal sealed class NonAdminCommands(List<MUnit> items) : CategoryBase<MUnit>(items);
internal sealed class MSFTSecBaselines_OptionalOverrides(List<MUnit> items) : CategoryBase<MUnit>(items);

/// <summary>
/// The main data type used for import/export of JSON Traverse data.
/// </summary>
internal sealed class MContainer(
	int total,
	int compliant,
	int nonCompliant,

	MicrosoftSecurityBaseline? microsoftSecurityBaseline = null,
	Microsoft365AppsSecurityBaseline? microsoft365AppsSecurityBaseline = null,
	MicrosoftDefender? microsoftDefender = null,
	AttackSurfaceReductionRules? attackSurfaceReductionRules = null,
	BitLockerSettings? bitLockerSettings = null,
	TLSSecurity? tlsSecurity = null,
	LockScreen? lockScreen = null,
	UserAccountControl? userAccountControl = null,
	DeviceGuard? deviceGuard = null,
	WindowsFirewall? windowsFirewall = null,
	OptionalWindowsFeatures? optionalWindowsFeatures = null,
	WindowsNetworking? windowsNetworking = null,
	MiscellaneousConfigurations? miscellaneousConfigurations = null,
	WindowsUpdateConfigurations? windowsUpdateConfigurations = null,
	EdgeBrowserConfigurations? edgeBrowserConfigurations = null,
	NonAdminCommands? nonAdminCommands = null,
	MSFTSecBaselines_OptionalOverrides? msftSecBaselines_OptionalOverrides = null,
	Arcane.CbomDocument? cryptographicBillOfMaterial = null)
{
	[JsonPropertyName("Time")]
	[JsonPropertyOrder(0)]
	public DateTime Time => DateTime.Now;

	[JsonPropertyName("MachineName")]
	[JsonPropertyOrder(1)]
	public string MachineName => Environment.MachineName;

	[JsonPropertyName("UserName")]
	[JsonPropertyOrder(2)]
	public string UserName => Environment.UserName;

	[JsonPropertyName("AppVersion")]
	[JsonPropertyOrder(3)]
	public string AppVersion => Atlas.currentAppVersion.ToString();

	[JsonInclude]
	[JsonPropertyName("Total")]
	[JsonPropertyOrder(4)]
	internal int Total => total;

	[JsonInclude]
	[JsonPropertyName("Compliant")]
	[JsonPropertyOrder(5)]
	internal int Compliant => compliant;

	[JsonInclude]
	[JsonPropertyName("NonCompliant")]
	[JsonPropertyOrder(6)]
	internal int NonCompliant => nonCompliant;

	[JsonInclude]
	[JsonPropertyName("MicrosoftSecurityBaseline")]
	[JsonPropertyOrder(7)]
	internal MicrosoftSecurityBaseline? MicrosoftSecurityBaseline => microsoftSecurityBaseline;

	[JsonInclude]
	[JsonPropertyName("Microsoft365AppsSecurityBaseline")]
	[JsonPropertyOrder(8)]
	internal Microsoft365AppsSecurityBaseline? Microsoft365AppsSecurityBaseline => microsoft365AppsSecurityBaseline;

	[JsonInclude]
	[JsonPropertyName("MicrosoftDefender")]
	[JsonPropertyOrder(9)]
	internal MicrosoftDefender? MicrosoftDefender => microsoftDefender;

	[JsonInclude]
	[JsonPropertyName("AttackSurfaceReductionRules")]
	[JsonPropertyOrder(10)]
	internal AttackSurfaceReductionRules? AttackSurfaceReductionRules => attackSurfaceReductionRules;

	[JsonInclude]
	[JsonPropertyName("BitLockerSettings")]
	[JsonPropertyOrder(11)]
	internal BitLockerSettings? BitLockerSettings => bitLockerSettings;

	[JsonInclude]
	[JsonPropertyName("TLSSecurity")]
	[JsonPropertyOrder(12)]
	internal TLSSecurity? TLSSecurity => tlsSecurity;

	[JsonInclude]
	[JsonPropertyName("LockScreen")]
	[JsonPropertyOrder(13)]
	internal LockScreen? LockScreen => lockScreen;

	[JsonInclude]
	[JsonPropertyName("UserAccountControl")]
	[JsonPropertyOrder(14)]
	internal UserAccountControl? UserAccountControl => userAccountControl;

	[JsonInclude]
	[JsonPropertyName("DeviceGuard")]
	[JsonPropertyOrder(15)]
	internal DeviceGuard? DeviceGuard => deviceGuard;

	[JsonInclude]
	[JsonPropertyName("WindowsFirewall")]
	[JsonPropertyOrder(16)]
	internal WindowsFirewall? WindowsFirewall => windowsFirewall;

	[JsonInclude]
	[JsonPropertyName("OptionalWindowsFeatures")]
	[JsonPropertyOrder(17)]
	[JsonConverter(typeof(DeserializationOverrides.OptionalWindowsFeaturesWriteOnlyConverter))]
	internal OptionalWindowsFeatures? OptionalWindowsFeatures => optionalWindowsFeatures;

	[JsonInclude]
	[JsonPropertyName("WindowsNetworking")]
	[JsonPropertyOrder(18)]
	internal WindowsNetworking? WindowsNetworking => windowsNetworking;

	[JsonInclude]
	[JsonPropertyName("MiscellaneousConfigurations")]
	[JsonPropertyOrder(19)]
	internal MiscellaneousConfigurations? MiscellaneousConfigurations => miscellaneousConfigurations;

	[JsonInclude]
	[JsonPropertyName("WindowsUpdateConfigurations")]
	[JsonPropertyOrder(20)]
	internal WindowsUpdateConfigurations? WindowsUpdateConfigurations => windowsUpdateConfigurations;

	[JsonInclude]
	[JsonPropertyName("EdgeBrowserConfigurations")]
	[JsonPropertyOrder(21)]
	internal EdgeBrowserConfigurations? EdgeBrowserConfigurations => edgeBrowserConfigurations;

	[JsonInclude]
	[JsonPropertyName("NonAdminCommands")]
	[JsonPropertyOrder(22)]
	internal NonAdminCommands? NonAdminCommands => nonAdminCommands;

	[JsonInclude]
	[JsonPropertyName("MSFTSecBaselines_OptionalOverrides")]
	[JsonPropertyOrder(23)]
	internal MSFTSecBaselines_OptionalOverrides? MSFTSecBaselines_OptionalOverrides => msftSecBaselines_OptionalOverrides;

	[JsonInclude]
	[JsonPropertyName("CryptographicBillOfMaterial")]
	[JsonPropertyOrder(24)]
	[JsonConverter(typeof(DeserializationOverrides.CryptographicBillOfMaterialWriteOnlyConverter))]
	internal Arcane.CbomDocument? CryptographicBillOfMaterial => cryptographicBillOfMaterial;
}

[JsonSourceGenerationOptions(
	WriteIndented = true,
	PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
	PropertyNameCaseInsensitive = false,
	DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
	NumberHandling = JsonNumberHandling.AllowReadingFromString,
	Converters = [
		typeof(JsonStringEnumConverter<Categories>),
		typeof(JsonStringEnumConverter<SubCategories>),
		typeof(JsonStringEnumConverter<Intent>),
		typeof(JsonStringEnumConverter<StatusState>),
		typeof(JsonStringEnumConverter<SecurityMeasureSource>),
		typeof(JsonStringEnumConverter<ASRRuleState>)
	]
)]
[JsonSerializable(typeof(MContainer))]
[JsonSerializable(typeof(MicrosoftSecurityBaseline))]
[JsonSerializable(typeof(Microsoft365AppsSecurityBaseline))]
[JsonSerializable(typeof(AttackSurfaceReductionRules))]
[JsonSerializable(typeof(OptionalWindowsFeatures))]
[JsonSerializable(typeof(MicrosoftDefender))]
[JsonSerializable(typeof(BitLockerSettings))]
[JsonSerializable(typeof(TLSSecurity))]
[JsonSerializable(typeof(LockScreen))]
[JsonSerializable(typeof(UserAccountControl))]
[JsonSerializable(typeof(DeviceGuard))]
[JsonSerializable(typeof(WindowsFirewall))]
[JsonSerializable(typeof(WindowsNetworking))]
[JsonSerializable(typeof(MiscellaneousConfigurations))]
[JsonSerializable(typeof(WindowsUpdateConfigurations))]
[JsonSerializable(typeof(EdgeBrowserConfigurations))]
[JsonSerializable(typeof(NonAdminCommands))]
[JsonSerializable(typeof(MSFTSecBaselines_OptionalOverrides))]
internal sealed partial class MContainerJsonContext : JsonSerializerContext
{
	/// <summary>
	/// Options used for writing the JSON files.
	/// </summary>
	private static readonly JsonWriterOptions WriterOptions = new()
	{
		Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
		Indented = true
	};

	/// <summary>
	/// Serialize a single <see cref="MContainer"/> instance.
	/// </summary>
	internal static void SerializeSingle(MContainer unit, string filePath)
	{
		ArrayBufferWriter<byte> buffer = new();
		Utf8JsonWriter writer = new(buffer, WriterOptions);

		try
		{
			JsonSerializer.Serialize(writer, unit, Default.MContainer);
		}
		finally
		{
			writer.Dispose();
		}

		// Make sure the file has a .json extension
		if (!string.Equals(Path.GetExtension(filePath), ".json", StringComparison.OrdinalIgnoreCase))
		{
			filePath += ".json";
		}

		// Make sure the folder that the user selected to save the report to exists
		string? directory = Path.GetDirectoryName(filePath);
		if (!string.IsNullOrEmpty(directory))
		{
			_ = Directory.CreateDirectory(directory);
		}

		File.WriteAllBytes(filePath, buffer.WrittenSpan);
	}

	/// <summary>
	/// Deserialize a JSON string into a single <see cref="MContainer"/> instance.
	/// </summary>
	internal static MContainer? DeserializeSingle(string json) => JsonSerializer.Deserialize(json, Default.MContainer);

	/// <summary>
	/// Loads a JSON file as an editable document and deserializes it into a <see cref="MContainer"/> instance.
	/// The document is kept so the file can later be saved back via <see cref="SaveEdited"/> without losing the parts that are not deserialized.
	/// </summary>
	/// <param name="filePath">Path to the JSON file.</param>
	/// <exception cref="InvalidOperationException">Thrown when the file content is invalid.</exception>
	internal static (JsonObject Root, MContainer Container) LoadEditable(string filePath)
	{
		JsonObject? root = JsonNode.Parse(File.ReadAllText(filePath))?.AsObject();
		MContainer? container = root?.Deserialize(Default.MContainer);

		if (root is null || container is null)
			throw new InvalidOperationException("Failed to deserialize the Traverse report into an MContainer instance.");

		return (root, container);
	}

	/// <summary>
	/// Saves the edited <see cref="MContainer"/> back to the JSON file it was loaded from via <see cref="LoadEditable"/>.
	/// Only the category sections and the summary counts are replaced in the original document.
	/// The metadata (Time, MachineName etc.) and the sections that are never deserialized (Optional Windows Features and CBOM) remain untouched.
	/// </summary>
	/// <param name="root">The document returned by <see cref="LoadEditable"/>.</param>
	/// <param name="container">The edited container returned by <see cref="LoadEditable"/>.</param>
	/// <param name="total">Total number of the items in all of the categories.</param>
	/// <param name="compliant">Number of the items that are marked as applied or compliant.</param>
	/// <param name="filePath">Path to the JSON file to overwrite.</param>
	internal static void SaveEdited(JsonObject root, MContainer container, int total, int compliant, string filePath)
	{
		JsonObject edited = JsonSerializer.SerializeToNode(container, Default.MContainer)!.AsObject();

		// Category sections are the only JSON objects among the top-level properties.
		foreach (KeyValuePair<string, JsonNode?> property in edited)
		{
			if (property.Value is JsonObject section)
			{
				root[property.Key] = section.DeepClone();
			}
		}

		root["Total"] = total;
		root["Compliant"] = compliant;
		root["NonCompliant"] = total - compliant;

		ArrayBufferWriter<byte> buffer = new();
		using (Utf8JsonWriter writer = new(buffer, WriterOptions))
		{
			root.WriteTo(writer);
		}

		File.WriteAllBytes(filePath, buffer.WrittenSpan);
	}

}
