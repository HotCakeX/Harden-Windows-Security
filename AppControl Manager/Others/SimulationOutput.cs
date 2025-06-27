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
	internal string? Path => path;

	/// <summary>
	/// Source from the Comparer function is always 'Signer'
	/// </summary>
	internal string Source => source;

	/// <summary>
	/// Whether the file is authorized or not
	/// </summary>
	internal bool IsAuthorized => isAuthorized;

	/// <summary>
	/// Gathered from the GetSignerInfo method
	/// </summary>
	internal string? SignerID => signerID;

	/// <summary>
	/// Gathered from the GetSignerInfo method
	/// </summary>
	internal string? SignerName => signerName;

	/// <summary>
	/// Gathered from the GetSignerInfo method
	/// </summary>
	internal string? SignerCertRoot => signerCertRoot;

	/// <summary>
	/// Gathered from the GetSignerInfo method
	/// </summary>
	internal string? SignerCertPublisher => signerCertPublisher;

	/// <summary>
	/// Gathered from the GetSignerInfo method
	/// </summary>
	internal string? SignerScope => signerScope;

	/// <summary>
	/// Gathered from the GetSignerInfo method
	/// </summary>
	internal List<string>? SignerFileAttributeIDs => signerFileAttributeIDs;

	/// <summary>
	/// The main level based on which the file is authorized
	/// </summary>
	internal string? MatchCriteria => matchCriteria;

	/// <summary>
	/// Only those eligible for FilePublisher, WHQLFilePublisher, or SignedVersion levels assign this value, otherwise it stays null
	/// </summary>
	internal string? SpecificFileNameLevelMatchCriteria => specificFileNameLevelMatchCriteria;

	/// <summary>
	/// Subject CN of the signer that allows the file
	/// </summary>
	internal string? CertSubjectCN => certSubjectCN;

	/// <summary>
	/// Issuer CN of the signer that allows the file
	/// </summary>
	internal string? CertIssuerCN => certIssuerCN;

	/// <summary>
	/// NotAfter date of the signer that allows the file
	/// </summary>
	internal string? CertNotAfter => certNotAfter;

	/// <summary>
	/// TBS value of the signer that allows the file
	/// </summary>
	internal string? CertTBSValue => certTBSValue;

	/// <summary>
	/// Full path of the file
	/// </summary>
	internal string? FilePath => filePath;

	/// <summary>
	/// Reference for the ViewModel's class
	/// </summary>
	internal SimulationVM? ParentViewModelSimulationVM { get; set; }
}
