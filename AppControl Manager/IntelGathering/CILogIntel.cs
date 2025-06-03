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

using System.Runtime.CompilerServices;

namespace AppControlManager.IntelGathering;

// Application Control event tags intelligence
internal static class CILogIntel
{
	/// <summary>
	/// Requested and Validated Signing Level Mappings: https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/operations/event-tag-explanations#requested-and-validated-signing-level
	/// </summary>
	private static readonly string?[] ReqValSigningLevels =
	[
		"Signing level hasn't yet been checked", // Index 0
		"File is unsigned or has no signature that passes the active policies", // Index 1
		"Trusted by App Control for Business policy", // Index 2
		"Developer signed code", // Index 3
		"Authenticode signed", // Index 4
		"Microsoft Store signed app PPL (Protected Process Light)", // Index 5
		"Microsoft Store-signed", // Index 6
		"Signed by an Antimalware vendor whose product is using AMPPL", // Index 7
		"Microsoft signed", // Index 8
		null, // Index 9 - does not exist
		null, // Index 10 - does not exist
		"Only used for signing of the .NET NGEN compiler", // Index 11
		"Windows signed", // Index 12
		null, // Index 13 - does not exist
		"Windows Trusted Computing Base signed" // Index 14
	];

	/// <summary>
	/// SignatureType Mappings: https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/operations/event-tag-explanations#signaturetype
	/// </summary>
	private static readonly string[] SignatureTypeTable =
	[
		"Unsigned or verification hasn't been attempted", // Index 0
		"Embedded signature", // Index 1
		"Cached signature; presence of a CI EA means the file was previously verified", // Index 2
		"Cached catalog verified via Catalog Database or searching catalog directly", // Index 3
		"Uncached catalog verified via Catalog Database or searching catalog directly", // Index 4
		"Successfully verified using an EA that informs CI that catalog to try first", // Index 5
		"AppX / MSIX package catalog verified", // Index 6
		"File was verified" // Index 7
	];

	/// <summary>
	/// VerificationError mappings: https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/operations/event-tag-explanations#verificationerror
	/// </summary>
	private static readonly string[] VerificationErrorTable =
	[
		"Successfully verified signature.", // Index 0
		"File has an invalid hash.", // Index 1
		"File contains shared writable sections.", // Index 2
		"File isn't signed.", // Index 3
		"Revoked signature.", // Index 4
		"Expired signature.", // Index 5
		"File is signed using a weak hashing algorithm, which doesn't meet the minimum policy.", // Index 6
		"Invalid root certificate.", // Index 7
		"Signature was unable to be validated; generic error.", // Index 8
		"Signing time not trusted.", // Index 9
		"The file must be signed using page hashes for this scenario.", // Index 10
		"Page hash mismatch.", // Index 11
		"Not valid for a PPL (Protected Process Light).", // Index 12
		"Not valid for a PP (Protected Process).", // Index 13
		"The signature is missing the required ARM processor EKU.", // Index 14
		"Failed WHQL check.", // Index 15
		"Default policy signing level not met.", // Index 16
		"Custom policy signing level not met; returned when signature doesn't validate against an SBCP-defined set of certs.", // Index 17
		"Custom signing level not met; returned if signature fails to match CISigners in UMCI.", // Index 18
		"Binary is revoked based on its file hash.", // Index 19
		"SHA1 cert hash's timestamp is missing or after valid cutoff as defined by Weak Crypto Policy.", // Index 20
		"Failed to pass App Control for Business policy.", // Index 21
		"Not Isolated User Mode (IUM) signed; indicates an attempt to load a standard Windows binary into a virtualization-based security (VBS) trustlet.", // Index 22
		"Invalid image hash. This error can indicate file corruption or a problem with the file's signature. Signatures using elliptic curve cryptography (ECC), such as ECDSA, return this VerificationError.", // Index 23
		"Flight root not allowed; indicates trying to run flight-signed code on production OS.", // Index 24
		"Anti-cheat policy violation.", // Index 25
		"Explicitly denied by App Control policy.", // Index 26
		"The signing chain appears to be tampered / invalid.", // Index 27
		"Resource page hash mismatch." // Index 28
	];


	// Array length constants for performance optimization
	private const uint ReqValSigningLevelsLength = 15;
	private const uint SignatureTypeTableLength = 8;
	private const uint VerificationErrorTableLength = 29;


	/// <summary>
	/// Resolves the Validated/Requested Signing Level int to friendly string
	/// </summary>
	/// <param name="SigningLevelInt"></param>
	/// <returns></returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static string? GetValidatedRequestedSigningLevel(int? SigningLevelInt)
	{
		if (SigningLevelInt.HasValue)
		{
			if ((uint)SigningLevelInt.Value < ReqValSigningLevelsLength)
			{
				return ReqValSigningLevels[SigningLevelInt.Value];
			}
			else
			{
				return null;
			}
		}
		else
		{
			return null;
		}
	}

	/// <summary>
	/// Resolves the VerificationError int to a friendly string
	/// </summary>
	/// <param name="VerificationError"></param>
	/// <returns></returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static string? GetVerificationError(int? VerificationError)
	{
		if (VerificationError.HasValue)
		{
			if ((uint)VerificationError.Value < VerificationErrorTableLength)
			{
				return VerificationErrorTable[VerificationError.Value];
			}
			else
			{
				return null;
			}
		}
		else
		{
			return null;
		}
	}

	/// <summary>
	/// Resolves the SignatureType int to a friendly string
	/// </summary>
	/// <param name="SignatureType"></param>
	/// <returns></returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static string? GetSignatureType(int? SignatureType)
	{
		if (SignatureType.HasValue)
		{
			if ((uint)SignatureType.Value < SignatureTypeTableLength)
			{
				return SignatureTypeTable[SignatureType.Value];
			}
			else
			{
				return null;
			}
		}
		else
		{
			return null;
		}
	}

}
