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
	// The name of the file, which is a truncated version of its path
	internal string? Path { get; set; } = path;

	// Source from the Comparer function is always 'Signer'
	internal string Source { get; set; } = source;

	// Whether the file is authorized or not
	internal bool IsAuthorized { get; set; } = isAuthorized;

	// Gathered from the GetSignerInfo method
	internal string? SignerID { get; set; } = signerID;

	// Gathered from the GetSignerInfo method
	internal string? SignerName { get; set; } = signerName;

	// Gathered from the GetSignerInfo method
	internal string? SignerCertRoot { get; set; } = signerCertRoot;

	// Gathered from the GetSignerInfo method
	internal string? SignerCertPublisher { get; set; } = signerCertPublisher;

	// Gathered from the GetSignerInfo method
	internal string? SignerScope { get; set; } = signerScope;

	// Gathered from the GetSignerInfo method
	internal List<string>? SignerFileAttributeIDs { get; set; } = signerFileAttributeIDs;

	// The main level based on which the file is authorized
	internal string? MatchCriteria { get; set; } = matchCriteria;

	// Only those eligible for FilePublisher, WHQLFilePublisher, or SignedVersion levels assign this value, otherwise it stays null
	internal string? SpecificFileNameLevelMatchCriteria { get; set; } = specificFileNameLevelMatchCriteria;

	// Subject CN of the signer that allows the file
	internal string? CertSubjectCN { get; set; } = certSubjectCN;

	// Issuer CN of the signer that allows the file
	internal string? CertIssuerCN { get; set; } = certIssuerCN;

	// NotAfter date of the signer that allows the file
	internal string? CertNotAfter { get; set; } = certNotAfter;

	// TBS value of the signer that allows the file
	internal string? CertTBSValue { get; set; } = certTBSValue;

	// Full path of the file
	internal string? FilePath { get; set; } = filePath;

	// Reference for the ViewModel's class
	internal SimulationVM? ParentViewModelSimulationVM { get; set; }
}
