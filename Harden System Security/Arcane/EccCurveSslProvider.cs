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
using System.Text.Json.Serialization;

namespace HardenSystemSecurity.Arcane;

internal sealed class EccCurveSslProvider(
	string name,
	string oid,
	uint publicKeyLengthBits,
	uint curveType,
	uint flags
)
{
	[JsonInclude]
	internal string Name => name;
	[JsonInclude]
	internal string Oid => oid;
	[JsonInclude]
	internal uint PublicKeyLengthBits => publicKeyLengthBits;
	[JsonInclude]
	internal uint CurveType => curveType;
	[JsonInclude]
	internal uint Flags => flags;
}

/// <summary>
/// JSON source generated context for <see cref="EccCurveSslProvider"/> type.
/// </summary>
[JsonSourceGenerationOptions(
	WriteIndented = true
)]
[JsonSerializable(typeof(EccCurveSslProvider))]
[JsonSerializable(typeof(List<EccCurveSslProvider>))]
internal sealed partial class EccCurveSslProviderJsonSerializationContext : JsonSerializerContext
{
}
