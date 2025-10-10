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

internal sealed class CryptoAlgorithm
{
	[JsonInclude]
	internal string Name { get; set; } = string.Empty;
	[JsonInclude]
	internal uint OperationClass { get; set; }
	[JsonInclude]
	internal uint Flags { get; set; }
	[JsonInclude]
	internal string AlgorithmType { get; set; } = string.Empty;
	[JsonInclude]
	internal bool IsOpenable { get; set; } = false;
	[JsonInclude]
	internal bool IsPostQuantum { get; set; } = false;
	[JsonInclude]
	internal bool SupportsKeyGeneration { get; set; } = false;
	[JsonInclude]
	internal List<string> SupportedParameterSets { get; set; } = [];
}

/// <summary>
/// JSON source generated context for <see cref="CryptoAlgorithm"/> type.
/// </summary>
[JsonSourceGenerationOptions(
	WriteIndented = true
)]
[JsonSerializable(typeof(CryptoAlgorithm))]
[JsonSerializable(typeof(List<CryptoAlgorithm>))]
internal sealed partial class CryptoAlgorithmJsonSerializationContext : JsonSerializerContext
{
}
