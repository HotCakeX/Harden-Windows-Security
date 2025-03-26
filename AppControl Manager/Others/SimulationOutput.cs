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
using AppControlManager.ViewModels;

namespace AppControlManager.Others;

/// <summary>
/// Used by AppControl Simulations, the output of the comparer function/method
/// This class holds the details of the current file in the App Control Simulation comparer
/// </summary>
internal sealed class SimulationOutput(
	string? path,
	string source,
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
	internal string? Path { get; } = path;

	/// <summary>
	/// Source from the Comparer function is always 'Signer'
	/// </summary>
	internal string Source { get; } = source;

	/// <summary>
	/// Whether the file is authorized or not
	/// </summary>
	internal bool IsAuthorized { get; } = isAuthorized;

	/// <summary>
	/// Gathered from the GetSignerInfo method
	/// </summary>
	internal string? SignerID { get; } = signerID;

	/// <summary>
	/// Gathered from the GetSignerInfo method
	/// </summary>
	internal string? SignerName { get; } = signerName;

	/// <summary>
	/// Gathered from the GetSignerInfo method
	/// </summary>
	internal string? SignerCertRoot { get; } = signerCertRoot;

	/// <summary>
	/// Gathered from the GetSignerInfo method
	/// </summary>
	internal string? SignerCertPublisher { get; } = signerCertPublisher;

	/// <summary>
	/// Gathered from the GetSignerInfo method
	/// </summary>
	internal string? SignerScope { get; } = signerScope;

	/// <summary>
	/// Gathered from the GetSignerInfo method
	/// </summary>
	internal List<string>? SignerFileAttributeIDs { get; } = signerFileAttributeIDs;

	/// <summary>
	/// The main level based on which the file is authorized
	/// </summary>
	internal string? MatchCriteria { get; } = matchCriteria;

	/// <summary>
	/// Only those eligible for FilePublisher, WHQLFilePublisher, or SignedVersion levels assign this value, otherwise it stays null
	/// </summary>
	internal string? SpecificFileNameLevelMatchCriteria { get; } = specificFileNameLevelMatchCriteria;

	/// <summary>
	/// Subject CN of the signer that allows the file
	/// </summary>
	internal string? CertSubjectCN { get; } = certSubjectCN;

	/// <summary>
	/// Issuer CN of the signer that allows the file
	/// </summary>
	internal string? CertIssuerCN { get; } = certIssuerCN;

	/// <summary>
	/// NotAfter date of the signer that allows the file
	/// </summary>
	internal string? CertNotAfter { get; } = certNotAfter;

	/// <summary>
	/// TBS value of the signer that allows the file
	/// </summary>
	internal string? CertTBSValue { get; } = certTBSValue;

	/// <summary>
	/// Full path of the file
	/// </summary>
	internal string? FilePath { get; } = filePath;

	/// <summary>
	/// Reference for the ViewModel's class
	/// </summary>
	internal SimulationVM? ParentViewModelSimulationVM { get; set; }
}
