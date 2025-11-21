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

using System.Text.Json;
using System.Text.Json.Serialization;
using HardenSystemSecurity.Arcane;

namespace HardenSystemSecurity.Traverse;

/// <summary>
/// This class hosts overrides so certain classes are excempt from deserialization.
/// </summary>
internal static class DeserializationOverrides
{

	/// <summary>
	/// Write-only converter for <see cref="MContainer.OptionalWindowsFeatures"/>
	/// </summary>
	internal sealed class OptionalWindowsFeaturesWriteOnlyConverter : JsonConverter<OptionalWindowsFeatures>
	{
		public override OptionalWindowsFeatures? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
		{
			// Skip the entire object and return null.
			if (reader.TokenType == JsonTokenType.StartObject)
			{
				int startDepth = reader.CurrentDepth;
				while (reader.Read())
				{
					if (reader.TokenType == JsonTokenType.EndObject && reader.CurrentDepth == startDepth)
					{
						break;
					}
				}
			}
			else
			{
				_ = reader.Read();
			}
			return null;
		}

		// Delegate serialization to source-generated metadata for OptionalWindowsFeatures.
		public override void Write(Utf8JsonWriter writer, OptionalWindowsFeatures value, JsonSerializerOptions options) =>
			JsonSerializer.Serialize(writer, value, MContainerJsonContext.Default.OptionalWindowsFeatures);
	}

	/// <summary>
	/// Write-only converter for <see cref="MContainer.CryptographicBillOfMaterial"/>
	/// </summary>
	internal sealed class CryptographicBillOfMaterialWriteOnlyConverter : JsonConverter<Arcane.CbomDocument>
	{
		public override Arcane.CbomDocument? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
		{
			// Skip the entire JSON payload for CBOM and return null.
			if (reader.TokenType == JsonTokenType.StartObject || reader.TokenType == JsonTokenType.StartArray)
			{
				int startDepth = reader.CurrentDepth;
				JsonTokenType endToken = reader.TokenType == JsonTokenType.StartArray ? JsonTokenType.EndArray : JsonTokenType.EndObject;

				while (reader.Read())
				{
					if (reader.TokenType == endToken && reader.CurrentDepth == startDepth)
					{
						break;
					}
				}
			}
			else
			{
				_ = reader.Read();
			}
			return null;
		}

		// Delegate full serialization of CBOM to its own source-generated metadata.
		public override void Write(Utf8JsonWriter writer, Arcane.CbomDocument value, JsonSerializerOptions options) =>
			JsonSerializer.Serialize(writer, value, CbomDocumentJsonSerializationContext.Default.CbomDocument);
	}
}
