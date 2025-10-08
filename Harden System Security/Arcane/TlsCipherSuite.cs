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
using System.Text.Json.Serialization;

namespace HardenSystemSecurity.Arcane;

internal sealed class TlsCipherSuite(string name)
{
	[JsonInclude]
	internal string Name => name;
	[JsonInclude]
	internal List<uint> Protocols { get; set; } = [];
	[JsonInclude]
	internal List<string> ProtocolNames { get; set; } = [];
	[JsonInclude]
	internal string Cipher { get; set; } = string.Empty;
	[JsonInclude]
	internal uint CipherSuite { get; set; }
	[JsonInclude]
	internal string CipherSuiteHex => "0x" + CipherSuite.ToString("X4", CultureInfo.InvariantCulture);
	[JsonInclude]
	internal uint BaseCipherSuite { get; set; }
	[JsonInclude]
	internal string BaseCipherSuiteHex => "0x" + BaseCipherSuite.ToString("X4", CultureInfo.InvariantCulture);
	[JsonInclude]
	internal uint CipherLength { get; set; }
	[JsonInclude]
	internal uint CipherBlockLength { get; set; }
	[JsonInclude]
	internal string Hash { get; set; } = string.Empty;
	[JsonInclude]
	internal uint HashLength { get; set; }
	[JsonInclude]
	internal string Exchange { get; set; } = string.Empty;
	[JsonInclude]
	internal uint MinimumExchangeLength { get; set; }
	[JsonInclude]
	internal uint MaximumExchangeLength { get; set; }
	[JsonInclude]
	internal string Certificate { get; set; } = string.Empty;
	[JsonInclude]
	internal uint KeyType { get; set; }
}

/// <summary>
/// JSON source generated context for <see cref="TlsCipherSuite"/> type.
/// </summary>
[JsonSourceGenerationOptions(
	WriteIndented = true
)]
[JsonSerializable(typeof(TlsCipherSuite))]
[JsonSerializable(typeof(List<TlsCipherSuite>))]
internal sealed partial class TlsCipherSuiteJsonSerializationContext : JsonSerializerContext
{
}
