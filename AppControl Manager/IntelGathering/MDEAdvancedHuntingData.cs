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

namespace AppControlManager.IntelGathering;

// The following converters are needed for when parsing the MDE AH CSV file
// The parsing from JSON string via MS Graph doesn't require it, but we use it for both

internal sealed class NullableBoolJsonConverter : JsonConverter<bool?>
{
	public override bool? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
	{
		// If the token is a boolean, return it directly.
		if (reader.TokenType == JsonTokenType.True)
		{
			return true;
		}
		if (reader.TokenType == JsonTokenType.False)
		{
			return false;
		}

		// If the token is a string, attempt to parse it.
		if (reader.TokenType == JsonTokenType.String)
		{
			string? strValue = reader.GetString();
			if (bool.TryParse(strValue, out bool boolValue))
			{
				return boolValue;
			}
			// handle numeric strings "1" or "0", just for future proofing
			if (strValue == "1")
			{
				return true;
			}
			if (strValue == "0")
			{
				return false;
			}
		}

		// If the token is null, return null.
		if (reader.TokenType == JsonTokenType.Null)
		{
			return null;
		}

		// return null if conversion is not possible.
		return null;
	}

	public override void Write(Utf8JsonWriter writer, bool? value, JsonSerializerOptions options)
	{
		if (value.HasValue)
		{
			writer.WriteBooleanValue(value.Value);
		}
		else
		{
			writer.WriteNullValue();
		}
	}
}


internal sealed class NullableIntJsonConverter : JsonConverter<int?>
{
	public override int? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
	{
		// If the token is a number, read it directly.
		if (reader.TokenType == JsonTokenType.Number && reader.TryGetInt32(out int value))
		{
			return value;
		}

		// If the token is a string, try to parse it.
		if (reader.TokenType == JsonTokenType.String)
		{
			string? stringValue = reader.GetString();
			if (int.TryParse(stringValue, out value))
			{
				return value;
			}
		}

		// For any other token, return null
		return null;
	}

	public override void Write(Utf8JsonWriter writer, int? value, JsonSerializerOptions options)
	{
		if (value.HasValue)
		{
			writer.WriteNumberValue(value.Value);
		}
		else
		{
			writer.WriteNullValue();
		}
	}
}


internal sealed class NullableLongJsonConverter : JsonConverter<long?>
{
	public override long? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
	{
		// If the token is a long number, try to read it directly.
		if (reader.TokenType == JsonTokenType.Number && reader.TryGetInt64(out long value))
		{
			return value;
		}

		// If the token is a string, try to parse it.
		if (reader.TokenType == JsonTokenType.String)
		{
			string? stringValue = reader.GetString();
			if (long.TryParse(stringValue, out value))
			{
				return value;
			}
		}

		// Otherwise, return null
		return null;
	}

	public override void Write(Utf8JsonWriter writer, long? value, JsonSerializerOptions options)
	{
		if (value.HasValue)
		{
			writer.WriteNumberValue(value.Value);
		}
		else
		{
			writer.WriteNullValue();
		}
	}
}


// The top-level object because the JSON file contains a "results" array.
internal sealed class MDEAdvancedHuntingDataRootObject
{
	[JsonInclude]
	[JsonPropertyName("results")]
	internal List<MDEAdvancedHuntingData> Results { get; set; } = [];
}

// A custom converter on the type so that we can automatically merge properties
// from the nested AdditionalFields JSON.
// So this class contains its own properties + properties of the AdditionalFields class
[JsonConverter(typeof(MDEAdvancedHuntingDataConverter))]
internal sealed class MDEAdvancedHuntingData
{
	// Main properties (from the top-level JSON object)
	[JsonInclude]
	[JsonPropertyName("Timestamp")]
	internal string? Timestamp { get; set; }

	[JsonInclude]
	[JsonPropertyName("DeviceId")]
	internal string? DeviceId { get; set; }

	[JsonInclude]
	[JsonPropertyName("DeviceName")]
	internal string? DeviceName { get; set; }

	[JsonInclude]
	[JsonPropertyName("ActionType")]
	internal string? ActionType { get; set; }

	[JsonInclude]
	[JsonPropertyName("FileName")]
	internal string? FileName { get; set; }

	[JsonInclude]
	[JsonPropertyName("FolderPath")]
	internal string? FolderPath { get; set; }

	[JsonInclude]
	[JsonPropertyName("SHA1")]
	internal string? SHA1 { get; set; }

	[JsonInclude]
	[JsonPropertyName("SHA256")]
	internal string? SHA256 { get; set; }

	[JsonInclude]
	[JsonPropertyName("InitiatingProcessSHA1")]
	internal string? InitiatingProcessSHA1 { get; set; }

	[JsonInclude]
	[JsonPropertyName("InitiatingProcessSHA256")]
	internal string? InitiatingProcessSHA256 { get; set; }

	[JsonInclude]
	[JsonPropertyName("InitiatingProcessMD5")]
	internal string? InitiatingProcessMD5 { get; set; }

	[JsonInclude]
	[JsonPropertyName("InitiatingProcessFileName")]
	internal string? InitiatingProcessFileName { get; set; }

	[JsonInclude]
	[JsonPropertyName("InitiatingProcessFileSize")]
	internal string? InitiatingProcessFileSize { get; set; }

	[JsonInclude]
	[JsonPropertyName("InitiatingProcessFolderPath")]
	internal string? InitiatingProcessFolderPath { get; set; }

	[JsonInclude]
	[JsonPropertyName("InitiatingProcessId")]
	internal string? InitiatingProcessId { get; set; }

	[JsonInclude]
	[JsonPropertyName("InitiatingProcessCommandLine")]
	internal string? InitiatingProcessCommandLine { get; set; }

	[JsonInclude]
	[JsonPropertyName("InitiatingProcessCreationTime")]
	internal string? InitiatingProcessCreationTime { get; set; }

	[JsonInclude]
	[JsonPropertyName("InitiatingProcessAccountDomain")]
	internal string? InitiatingProcessAccountDomain { get; set; }

	[JsonInclude]
	[JsonPropertyName("InitiatingProcessAccountName")]
	internal string? InitiatingProcessAccountName { get; set; }

	[JsonInclude]
	[JsonPropertyName("InitiatingProcessAccountSid")]
	internal string? InitiatingProcessAccountSid { get; set; }

	[JsonInclude]
	[JsonPropertyName("InitiatingProcessVersionInfoCompanyName")]
	internal string? InitiatingProcessVersionInfoCompanyName { get; set; }

	[JsonInclude]
	[JsonPropertyName("InitiatingProcessVersionInfoProductName")]
	internal string? InitiatingProcessVersionInfoProductName { get; set; }

	[JsonInclude]
	[JsonPropertyName("InitiatingProcessVersionInfoProductVersion")]
	internal string? InitiatingProcessVersionInfoProductVersion { get; set; }

	[JsonInclude]
	[JsonPropertyName("InitiatingProcessVersionInfoInternalFileName")]
	internal string? InitiatingProcessVersionInfoInternalFileName { get; set; }

	[JsonInclude]
	[JsonPropertyName("InitiatingProcessVersionInfoOriginalFileName")]
	internal string? InitiatingProcessVersionInfoOriginalFileName { get; set; }

	[JsonInclude]
	[JsonPropertyName("InitiatingProcessVersionInfoFileDescription")]
	internal string? InitiatingProcessVersionInfoFileDescription { get; set; }

	[JsonInclude]
	[JsonPropertyName("InitiatingProcessParentId")]
	internal string? InitiatingProcessParentId { get; set; }

	[JsonInclude]
	[JsonPropertyName("InitiatingProcessParentFileName")]
	internal string? InitiatingProcessParentFileName { get; set; }

	[JsonInclude]
	[JsonPropertyName("InitiatingProcessParentCreationTime")]
	internal string? InitiatingProcessParentCreationTime { get; set; }

	[JsonInclude]
	[JsonPropertyName("InitiatingProcessLogonId")]
	internal string? InitiatingProcessLogonId { get; set; }

	[JsonInclude]
	[JsonPropertyName("ReportId")]
	internal string? ReportId { get; set; }

	// Additional fields merged from the AdditionalFields JSON string.
	[JsonInclude]
	[JsonPropertyName("PolicyID")]
	internal string? PolicyID { get; set; }

	[JsonInclude]
	[JsonPropertyName("PolicyName")]
	internal string? PolicyName { get; set; }

	[JsonInclude]
	[JsonPropertyName("RequestedSigningLevel")]
	internal string? RequestedSigningLevel { get; set; }

	[JsonInclude]
	[JsonPropertyName("ValidatedSigningLevel")]
	internal string? ValidatedSigningLevel { get; set; }

	[JsonInclude]
	[JsonPropertyName("ProcessName")]
	internal string? ProcessName { get; set; }

	[JsonInclude]
	[JsonPropertyName("StatusCode")]
	internal string? StatusCode { get; set; }

	[JsonInclude]
	[JsonPropertyName("Sha1FlatHash")]
	internal string? Sha1FlatHash { get; set; }

	[JsonInclude]
	[JsonPropertyName("Sha256FlatHash")]
	internal string? Sha256FlatHash { get; set; }

	[JsonInclude]
	[JsonPropertyName("USN")]
	[JsonConverter(typeof(NullableLongJsonConverter))]
	internal long? USN { get; set; }

	[JsonInclude]
	[JsonPropertyName("SiSigningScenario")]
	[JsonConverter(typeof(NullableIntJsonConverter))]
	internal int? SiSigningScenario { get; set; }

	[JsonInclude]
	[JsonPropertyName("PolicyHash")]
	internal string? PolicyHash { get; set; }

	[JsonInclude]
	[JsonPropertyName("PolicyGuid")]
	internal string? PolicyGuid { get; set; }

	[JsonInclude]
	[JsonPropertyName("UserWriteable")]
	[JsonConverter(typeof(NullableBoolJsonConverter))]
	internal bool? UserWriteable { get; set; }

	[JsonInclude]
	[JsonPropertyName("OriginalFileName")]
	internal string? OriginalFileName { get; set; }

	[JsonInclude]
	[JsonPropertyName("InternalName")]
	internal string? InternalName { get; set; }

	[JsonInclude]
	[JsonPropertyName("FileDescription")]
	internal string? FileDescription { get; set; }

	[JsonInclude]
	[JsonPropertyName("FileVersion")]
	internal string? FileVersion { get; set; }

	[JsonInclude]
	[JsonPropertyName("EtwActivityId")]
	internal string? EtwActivityId { get; set; }

	[JsonInclude]
	[JsonPropertyName("IssuerName")]
	internal string? IssuerName { get; set; }

	[JsonInclude]
	[JsonPropertyName("IssuerTBSHash")]
	internal string? IssuerTBSHash { get; set; }

	[JsonInclude]
	[JsonPropertyName("NotValidAfter")]
	internal string? NotValidAfter { get; set; }

	[JsonInclude]
	[JsonPropertyName("NotValidBefore")]
	internal string? NotValidBefore { get; set; }

	[JsonInclude]
	[JsonPropertyName("PublisherName")]
	internal string? PublisherName { get; set; }

	[JsonInclude]
	[JsonPropertyName("PublisherTBSHash")]
	internal string? PublisherTBSHash { get; set; }

	[JsonInclude]
	[JsonPropertyName("SignatureType")]
	internal string? SignatureType { get; set; }

	[JsonInclude]
	[JsonPropertyName("TotalSignatureCount")]
	[JsonConverter(typeof(NullableIntJsonConverter))]
	internal int? TotalSignatureCount { get; set; }

	[JsonInclude]
	[JsonPropertyName("VerificationError")]
	internal string? VerificationError { get; set; }

	[JsonInclude]
	[JsonPropertyName("Signature")]
	[JsonConverter(typeof(NullableIntJsonConverter))]
	internal int? Signature { get; set; }

	[JsonInclude]
	[JsonPropertyName("Hash")]
	internal string? Hash { get; set; }

	[JsonInclude]
	[JsonPropertyName("Flags")]
	[JsonConverter(typeof(NullableIntJsonConverter))]
	internal int? Flags { get; set; }

	[JsonInclude]
	[JsonPropertyName("PolicyBits")]
	[JsonConverter(typeof(NullableIntJsonConverter))]
	internal int? PolicyBits { get; set; }
}

// This type represents the additional fields that are stored as a JSON string
// inside the "AdditionalFields" property.
internal sealed class AdditionalFields
{
	[JsonInclude]
	[JsonPropertyName("PolicyID")]
	internal string? PolicyID { get; set; }

	[JsonInclude]
	[JsonPropertyName("PolicyName")]
	internal string? PolicyName { get; set; }

	[JsonInclude]
	[JsonPropertyName("RequestedSigningLevel")]
	internal string? RequestedSigningLevel { get; set; }

	[JsonInclude]
	[JsonPropertyName("ValidatedSigningLevel")]
	internal string? ValidatedSigningLevel { get; set; }

	[JsonInclude]
	[JsonPropertyName("ProcessName")]
	internal string? ProcessName { get; set; }

	[JsonInclude]
	[JsonPropertyName("StatusCode")]
	internal string? StatusCode { get; set; }

	[JsonInclude]
	[JsonPropertyName("Sha1FlatHash")]
	internal string? Sha1FlatHash { get; set; }

	[JsonInclude]
	[JsonPropertyName("Sha256FlatHash")]
	internal string? Sha256FlatHash { get; set; }

	[JsonInclude]
	[JsonPropertyName("USN")]
	[JsonConverter(typeof(NullableLongJsonConverter))]
	internal long? USN { get; set; }

	[JsonInclude]
	[JsonPropertyName("SiSigningScenario")]
	[JsonConverter(typeof(NullableIntJsonConverter))]
	internal int? SiSigningScenario { get; set; }

	[JsonInclude]
	[JsonPropertyName("PolicyHash")]
	internal string? PolicyHash { get; set; }

	[JsonInclude]
	[JsonPropertyName("PolicyGuid")]
	internal string? PolicyGuid { get; set; }

	[JsonInclude]
	[JsonPropertyName("UserWriteable")]
	[JsonConverter(typeof(NullableBoolJsonConverter))]
	internal bool? UserWriteable { get; set; }

	[JsonInclude]
	[JsonPropertyName("OriginalFileName")]
	internal string? OriginalFileName { get; set; }

	[JsonInclude]
	[JsonPropertyName("InternalName")]
	internal string? InternalName { get; set; }

	[JsonInclude]
	[JsonPropertyName("FileDescription")]
	internal string? FileDescription { get; set; }

	[JsonInclude]
	[JsonPropertyName("FileVersion")]
	internal string? FileVersion { get; set; }

	[JsonInclude]
	[JsonPropertyName("EtwActivityId")]
	internal string? EtwActivityId { get; set; }

	[JsonInclude]
	[JsonPropertyName("IssuerName")]
	internal string? IssuerName { get; set; }

	[JsonInclude]
	[JsonPropertyName("IssuerTBSHash")]
	internal string? IssuerTBSHash { get; set; }

	[JsonInclude]
	[JsonPropertyName("NotValidAfter")]
	internal string? NotValidAfter { get; set; }

	[JsonInclude]
	[JsonPropertyName("NotValidBefore")]
	internal string? NotValidBefore { get; set; }

	[JsonInclude]
	[JsonPropertyName("PublisherName")]
	internal string? PublisherName { get; set; }

	[JsonInclude]
	[JsonPropertyName("PublisherTBSHash")]
	internal string? PublisherTBSHash { get; set; }

	[JsonInclude]
	[JsonPropertyName("SignatureType")]
	internal string? SignatureType { get; set; }

	[JsonInclude]
	[JsonPropertyName("TotalSignatureCount")]
	[JsonConverter(typeof(NullableIntJsonConverter))]
	internal int? TotalSignatureCount { get; set; }

	[JsonInclude]
	[JsonPropertyName("VerificationError")]
	internal string? VerificationError { get; set; }

	[JsonInclude]
	[JsonPropertyName("Signature")]
	[JsonConverter(typeof(NullableIntJsonConverter))]
	internal int? Signature { get; set; }

	[JsonInclude]
	[JsonPropertyName("Hash")]
	internal string? Hash { get; set; }

	[JsonInclude]
	[JsonPropertyName("Flags")]
	[JsonConverter(typeof(NullableIntJsonConverter))]
	internal int? Flags { get; set; }

	[JsonInclude]
	[JsonPropertyName("PolicyBits")]
	[JsonConverter(typeof(NullableIntJsonConverter))]
	internal int? PolicyBits { get; set; }
}

// Custom converter for MDEAdvancedHuntingData that reads both the top-level properties
// and, if present, parses the AdditionalFields string (which is JSON) into an AdditionalFields instance.
internal sealed class MDEAdvancedHuntingDataConverter : JsonConverter<MDEAdvancedHuntingData>
{
	public override MDEAdvancedHuntingData Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
	{
		using JsonDocument document = JsonDocument.ParseValue(ref reader);
		JsonElement root = document.RootElement;

		MDEAdvancedHuntingData result = new()
		{
			// Main properties
			Timestamp = GetStringOrNull(root, "Timestamp"),
			DeviceId = GetStringOrNull(root, "DeviceId"),
			DeviceName = GetStringOrNull(root, "DeviceName"),
			ActionType = GetStringOrNull(root, "ActionType"),
			FileName = GetStringOrNull(root, "FileName"),
			FolderPath = GetStringOrNull(root, "FolderPath"),
			SHA1 = GetStringOrNull(root, "SHA1"),
			SHA256 = GetStringOrNull(root, "SHA256"),
			InitiatingProcessSHA1 = GetStringOrNull(root, "InitiatingProcessSHA1"),
			InitiatingProcessSHA256 = GetStringOrNull(root, "InitiatingProcessSHA256"),
			InitiatingProcessMD5 = GetStringOrNull(root, "InitiatingProcessMD5"),
			InitiatingProcessFileName = GetStringOrNull(root, "InitiatingProcessFileName"),
			InitiatingProcessFileSize = GetStringOrNull(root, "InitiatingProcessFileSize"),
			InitiatingProcessFolderPath = GetStringOrNull(root, "InitiatingProcessFolderPath"),
			InitiatingProcessId = GetStringOrNull(root, "InitiatingProcessId"),
			InitiatingProcessCommandLine = GetStringOrNull(root, "InitiatingProcessCommandLine"),
			InitiatingProcessCreationTime = GetStringOrNull(root, "InitiatingProcessCreationTime"),
			InitiatingProcessAccountDomain = GetStringOrNull(root, "InitiatingProcessAccountDomain"),
			InitiatingProcessAccountName = GetStringOrNull(root, "InitiatingProcessAccountName"),
			InitiatingProcessAccountSid = GetStringOrNull(root, "InitiatingProcessAccountSid"),
			InitiatingProcessVersionInfoCompanyName = GetStringOrNull(root, "InitiatingProcessVersionInfoCompanyName"),
			InitiatingProcessVersionInfoProductName = GetStringOrNull(root, "InitiatingProcessVersionInfoProductName"),
			InitiatingProcessVersionInfoProductVersion = GetStringOrNull(root, "InitiatingProcessVersionInfoProductVersion"),
			InitiatingProcessVersionInfoInternalFileName = GetStringOrNull(root, "InitiatingProcessVersionInfoInternalFileName"),
			InitiatingProcessVersionInfoOriginalFileName = GetStringOrNull(root, "InitiatingProcessVersionInfoOriginalFileName"),
			InitiatingProcessVersionInfoFileDescription = GetStringOrNull(root, "InitiatingProcessVersionInfoFileDescription"),
			InitiatingProcessParentId = GetStringOrNull(root, "InitiatingProcessParentId"),
			InitiatingProcessParentFileName = GetStringOrNull(root, "InitiatingProcessParentFileName"),
			InitiatingProcessParentCreationTime = GetStringOrNull(root, "InitiatingProcessParentCreationTime"),
			InitiatingProcessLogonId = GetStringOrNull(root, "InitiatingProcessLogonId"),
			ReportId = GetStringOrNull(root, "ReportId")
		};

		// If the JSON element contains an AdditionalFields property,
		// parse its string value (which is expected to be JSON) into an AdditionalFields instance
		// using the source-generated context.
		if (root.TryGetProperty("AdditionalFields", out JsonElement additionalFieldsElement))
		{
			if (additionalFieldsElement.ValueKind == JsonValueKind.String)
			{
				string? additionalJson = additionalFieldsElement.GetString();
				if (!string.IsNullOrWhiteSpace(additionalJson))
				{
					AdditionalFields? additional = JsonSerializer.Deserialize(
						additionalJson,
						MDEAdvancedHuntingJSONSerializationContext.Default.AdditionalFields);
					if (additional is not null)
					{
						result.PolicyID = additional.PolicyID;
						result.PolicyName = additional.PolicyName;
						result.RequestedSigningLevel = additional.RequestedSigningLevel;
						result.ValidatedSigningLevel = additional.ValidatedSigningLevel;
						result.ProcessName = additional.ProcessName;
						result.StatusCode = additional.StatusCode;
						result.Sha1FlatHash = additional.Sha1FlatHash;
						result.Sha256FlatHash = additional.Sha256FlatHash;
						result.USN = additional.USN;
						result.SiSigningScenario = additional.SiSigningScenario;
						result.PolicyHash = additional.PolicyHash;
						result.PolicyGuid = additional.PolicyGuid;
						result.UserWriteable = additional.UserWriteable;
						result.OriginalFileName = additional.OriginalFileName;
						result.InternalName = additional.InternalName;
						result.FileDescription = additional.FileDescription;
						result.FileVersion = additional.FileVersion;
						result.EtwActivityId = additional.EtwActivityId;
						result.IssuerName = additional.IssuerName;
						result.IssuerTBSHash = additional.IssuerTBSHash;
						result.NotValidAfter = additional.NotValidAfter;
						result.NotValidBefore = additional.NotValidBefore;
						result.PublisherName = additional.PublisherName;
						result.PublisherTBSHash = additional.PublisherTBSHash;
						result.SignatureType = additional.SignatureType;
						result.TotalSignatureCount = additional.TotalSignatureCount;
						result.VerificationError = additional.VerificationError;
						result.Signature = additional.Signature;
						result.Hash = additional.Hash;
						result.Flags = additional.Flags;
						result.PolicyBits = additional.PolicyBits;
					}
				}
			}
		}

		return result;
	}

	public override void Write(Utf8JsonWriter writer, MDEAdvancedHuntingData value, JsonSerializerOptions options)
	{
		writer.WriteStartObject();

		// Write main properties
		writer.WriteString("Timestamp", value.Timestamp);
		writer.WriteString("DeviceId", value.DeviceId);
		writer.WriteString("DeviceName", value.DeviceName);
		writer.WriteString("ActionType", value.ActionType);
		writer.WriteString("FileName", value.FileName);
		writer.WriteString("FolderPath", value.FolderPath);
		writer.WriteString("SHA1", value.SHA1);
		writer.WriteString("SHA256", value.SHA256);
		writer.WriteString("InitiatingProcessSHA1", value.InitiatingProcessSHA1);
		writer.WriteString("InitiatingProcessSHA256", value.InitiatingProcessSHA256);
		writer.WriteString("InitiatingProcessMD5", value.InitiatingProcessMD5);
		writer.WriteString("InitiatingProcessFileName", value.InitiatingProcessFileName);
		writer.WriteString("InitiatingProcessFileSize", value.InitiatingProcessFileSize);
		writer.WriteString("InitiatingProcessFolderPath", value.InitiatingProcessFolderPath);
		writer.WriteString("InitiatingProcessId", value.InitiatingProcessId);
		writer.WriteString("InitiatingProcessCommandLine", value.InitiatingProcessCommandLine);
		writer.WriteString("InitiatingProcessCreationTime", value.InitiatingProcessCreationTime);
		writer.WriteString("InitiatingProcessAccountDomain", value.InitiatingProcessAccountDomain);
		writer.WriteString("InitiatingProcessAccountName", value.InitiatingProcessAccountName);
		writer.WriteString("InitiatingProcessAccountSid", value.InitiatingProcessAccountSid);
		writer.WriteString("InitiatingProcessVersionInfoCompanyName", value.InitiatingProcessVersionInfoCompanyName);
		writer.WriteString("InitiatingProcessVersionInfoProductName", value.InitiatingProcessVersionInfoProductName);
		writer.WriteString("InitiatingProcessVersionInfoProductVersion", value.InitiatingProcessVersionInfoProductVersion);
		writer.WriteString("InitiatingProcessVersionInfoInternalFileName", value.InitiatingProcessVersionInfoInternalFileName);
		writer.WriteString("InitiatingProcessVersionInfoOriginalFileName", value.InitiatingProcessVersionInfoOriginalFileName);
		writer.WriteString("InitiatingProcessVersionInfoFileDescription", value.InitiatingProcessVersionInfoFileDescription);
		writer.WriteString("InitiatingProcessParentId", value.InitiatingProcessParentId);
		writer.WriteString("InitiatingProcessParentFileName", value.InitiatingProcessParentFileName);
		writer.WriteString("InitiatingProcessParentCreationTime", value.InitiatingProcessParentCreationTime);
		writer.WriteString("InitiatingProcessLogonId", value.InitiatingProcessLogonId);
		writer.WriteString("ReportId", value.ReportId);

		// Create an AdditionalFields instance from the additional properties.
		AdditionalFields additional = new()
		{
			PolicyID = value.PolicyID,
			PolicyName = value.PolicyName,
			RequestedSigningLevel = value.RequestedSigningLevel,
			ValidatedSigningLevel = value.ValidatedSigningLevel,
			ProcessName = value.ProcessName,
			StatusCode = value.StatusCode,
			Sha1FlatHash = value.Sha1FlatHash,
			Sha256FlatHash = value.Sha256FlatHash,
			USN = value.USN,
			SiSigningScenario = value.SiSigningScenario,
			PolicyHash = value.PolicyHash,
			PolicyGuid = value.PolicyGuid,
			UserWriteable = value.UserWriteable,
			OriginalFileName = value.OriginalFileName,
			InternalName = value.InternalName,
			FileDescription = value.FileDescription,
			FileVersion = value.FileVersion,
			EtwActivityId = value.EtwActivityId,
			IssuerName = value.IssuerName,
			IssuerTBSHash = value.IssuerTBSHash,
			NotValidAfter = value.NotValidAfter,
			NotValidBefore = value.NotValidBefore,
			PublisherName = value.PublisherName,
			PublisherTBSHash = value.PublisherTBSHash,
			SignatureType = value.SignatureType,
			TotalSignatureCount = value.TotalSignatureCount,
			VerificationError = value.VerificationError,
			Signature = value.Signature,
			Hash = value.Hash,
			Flags = value.Flags,
			PolicyBits = value.PolicyBits
		};

		// Serialize the AdditionalFields object using the source-generated context.
		string additionalFieldsJson = JsonSerializer.Serialize(
			additional,
			MDEAdvancedHuntingJSONSerializationContext.Default.AdditionalFields);
		writer.WriteString("AdditionalFields", additionalFieldsJson);

		writer.WriteEndObject();
	}

	private static string? GetStringOrNull(JsonElement element, string propertyName)
	{
		if (element.TryGetProperty(propertyName, out JsonElement prop))
		{
			return prop.ValueKind == JsonValueKind.String ? prop.GetString() : prop.ToString();
		}
		return null;
	}
}

// This partial class tells System.Text.Json which types to generate serialization code for.
[JsonSerializable(typeof(MDEAdvancedHuntingDataRootObject))]
[JsonSerializable(typeof(AdditionalFields))]
[JsonSourceGenerationOptions(WriteIndented = true)]
internal sealed partial class MDEAdvancedHuntingJSONSerializationContext : JsonSerializerContext
{
}
