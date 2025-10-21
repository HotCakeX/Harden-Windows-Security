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

namespace AppControlManager.Others;

/// <summary>
/// Used by AppControl Simulations, the output of the <see cref="SimulationMethods.Arbitrator"/>.
/// This class holds the details of the current file in the App Control Simulation arbitrator.
/// </summary>
internal sealed class SimulationOutput(
	string? path,
	SimulationMethods.SimulationOutputSource source,
	bool isAuthorized,
	string? signerID,
	string? signerName,
	string? signerCertRoot,
	string? signerCertPublisher,
	string? signerScope,
	List<string>? signerFileAttributeIDs,
	string? matchCriteria,
	string? specificFileNameLevelMatchCriteria,
	string? certSubjectCN,
	string? certIssuerCN,
	string? certNotAfter,
	string? certTBSValue,
	string? filePath
)
{
	/// <summary>
	/// The name of the file, which is a truncated version of its path
	/// </summary>
	[JsonInclude]
	internal string? Path => path;

	/// <summary>
	/// Values from the <see cref="SimulationMethods.SimulationOutputSource"/> enum.
	/// Using <see cref="JsonConverter"/> exports the actual strings of enums instead of their numbers.
	/// </summary>
	[JsonInclude]
	[JsonConverter(typeof(JsonStringEnumConverter<SimulationMethods.SimulationOutputSource>))]
	internal SimulationMethods.SimulationOutputSource Source => source;

	/// <summary>
	/// Whether the file is authorized or not
	/// </summary>
	[JsonInclude]
	internal bool IsAuthorized => isAuthorized;

	/// <summary>
	/// Gathered from the GetSignerInfo method
	/// </summary>
	[JsonInclude]
	internal string? SignerID => signerID;

	/// <summary>
	/// Gathered from the GetSignerInfo method
	/// </summary>
	[JsonInclude]
	internal string? SignerName => signerName;

	/// <summary>
	/// Gathered from the GetSignerInfo method
	/// </summary>
	[JsonInclude]
	internal string? SignerCertRoot => signerCertRoot;

	/// <summary>
	/// Gathered from the GetSignerInfo method
	/// </summary>
	[JsonInclude]
	internal string? SignerCertPublisher => signerCertPublisher;

	/// <summary>
	/// Gathered from the GetSignerInfo method
	/// </summary>
	[JsonInclude]
	internal string? SignerScope => signerScope;

	/// <summary>
	/// Gathered from the GetSignerInfo method
	/// </summary>
	[JsonInclude]
	internal List<string>? SignerFileAttributeIDs => signerFileAttributeIDs;

	/// <summary>
	/// The main level based on which the file is authorized
	/// </summary>
	[JsonInclude]
	internal string? MatchCriteria => matchCriteria;

	/// <summary>
	/// Only those eligible for FilePublisher, WHQLFilePublisher, or SignedVersion levels assign this value, otherwise it stays null
	/// </summary>
	[JsonInclude]
	internal string? SpecificFileNameLevelMatchCriteria => specificFileNameLevelMatchCriteria;

	/// <summary>
	/// Subject CN of the signer that allows the file
	/// </summary>
	[JsonInclude]
	internal string? CertSubjectCN => certSubjectCN;

	/// <summary>
	/// Issuer CN of the signer that allows the file
	/// </summary>
	[JsonInclude]
	internal string? CertIssuerCN => certIssuerCN;

	/// <summary>
	/// NotAfter date of the signer that allows the file
	/// </summary>
	[JsonInclude]
	internal string? CertNotAfter => certNotAfter;

	/// <summary>
	/// TBS value of the signer that allows the file
	/// </summary>
	[JsonInclude]
	internal string? CertTBSValue => certTBSValue;

	/// <summary>
	/// Full path of the file
	/// </summary>
	[JsonInclude]
	internal string? FilePath => filePath;
}

/// <summary>
/// JSON source generated context for <see cref="SimulationOutput"/>.
/// </summary>
[JsonSourceGenerationOptions(
	WriteIndented = true
)]
[JsonSerializable(typeof(SimulationOutput))]
[JsonSerializable(typeof(List<SimulationOutput>))]
internal sealed partial class SimulationOutputJsonContext : JsonSerializerContext
{
}
