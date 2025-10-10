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
using System.Runtime.InteropServices;
using System.Text.Json.Serialization;

namespace HardenSystemSecurity.Arcane;

/// <summary>
/// CBOM container.
/// </summary>
internal sealed class CbomDocument(
	List<CryptoAlgorithm> algorithms,
	List<EccCurveCng> cngCurves,
	List<EccCurveSslProvider> sslProviderCurves,
	List<TlsCipherSuite> tlsCipherSuites,
	List<string> registeredProviders
	)
{
	[JsonInclude]
	internal string BomFormat => "CBOM";

	[JsonInclude]
	internal string SpecVersion => "1.0";

	[JsonInclude]
	internal CbomMetadata Metadata => new();

	[JsonInclude]
	internal List<CryptoAlgorithm> Algorithms => algorithms;

	[JsonInclude]
	internal List<EccCurveCng> CngCurves => cngCurves;

	[JsonInclude]
	internal List<EccCurveSslProvider> SslProviderCurves => sslProviderCurves;

	[JsonInclude]
	internal List<TlsCipherSuite> TlsCipherSuites => tlsCipherSuites;

	[JsonInclude]
	internal List<string> RegisteredProviders => registeredProviders;
}

internal sealed class CbomMetadata
{
	[JsonInclude]
	internal string Timestamp => DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

	[JsonInclude]
	internal CbomHost Host => new();

	[JsonInclude]
	internal CbomTool Tool => new();
}

internal sealed class CbomHost
{
	[JsonInclude]
	internal string Machine => Environment.MachineName;

	[JsonInclude]
	internal string OsVersion => Helpers.GetOsVersion();

	[JsonInclude]
	internal string Architecture => RuntimeInformation.OSArchitecture.ToString();

	[JsonInclude]
	internal bool IsFIPSPolicyEnabled => Helpers.IsFIPSEnabled();
}


internal static class Helpers
{
	internal static string GetOsVersion()
	{
		string descr = RuntimeInformation.OSDescription;
		return string.IsNullOrWhiteSpace(descr) ? Environment.OSVersion.VersionString : descr;
	}

	internal static bool IsFIPSEnabled()
	{
		int status = NativeMethods.BCryptGetFipsAlgorithmMode(out byte enabled);
		if (status == 0)
		{
			return enabled != 0;
		}
		return false;
	}
}

internal sealed class CbomTool
{
	[JsonInclude]
	internal string Name => "Harden System Security Application";

	[JsonInclude]
	internal string Website => "https://github.com/HotCakeX/Harden-Windows-Security";

	[JsonInclude]
	internal string Version => App.currentAppVersion.ToString();
}

/// <summary>
/// JSON source generation context for the canonical CBOM container.
/// </summary>
[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(CbomDocument))]
[JsonSerializable(typeof(List<string>))]
internal sealed partial class CbomDocumentJsonSerializationContext : JsonSerializerContext
{
}
