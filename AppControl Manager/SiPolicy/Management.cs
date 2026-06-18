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
using System.IO;
using System.Xml;
using AppControlManager.Main;

namespace AppControlManager.SiPolicy;

internal static class Management
{
	/// <summary>
	/// Initializes the <see cref="SiPolicy.SiPolicy"/> object by accepting a string path to a valid XML file or an XmlDocument object.
	/// </summary>
	/// <param name="xmlFilePath"></param>
	/// <param name="XmlObj"></param>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static SiPolicy Initialize(string? xmlFilePath, XmlDocument? XmlObj) =>
		 CustomDeserialization.DeserializeSiPolicy(xmlFilePath, XmlObj);

	/// <summary>
	/// Converts a Code Integrity policy to CIP binary file.
	/// </summary>
	/// <param name="xmlFilePath"></param>
	/// <param name="BinPath"></param>
	internal static void ConvertXMLToBinary(string? xmlFilePath, string BinPath)
	{
		if (File.Exists(BinPath))
			File.Delete(BinPath);

		SiPolicy policyObj = CustomDeserialization.DeserializeSiPolicy(xmlFilePath, null);
		using FileStream honeyStream = new(BinPath, FileMode.Create, FileAccess.ReadWrite);
		BinaryOpsForward.ConvertPolicyToBinary(policyObj, honeyStream);
	}

	internal static void ConvertXMLToBinary(SiPolicy policyObj, string BinPath)
	{
		using FileStream honeyStream = new(BinPath, FileMode.Create, FileAccess.ReadWrite);
		BinaryOpsForward.ConvertPolicyToBinary(policyObj, honeyStream);
	}

	/// <summary>
	/// Converts a SiPolicy object to bytes array (CIP binary format).
	/// </summary>
	/// <param name="policyObj">The SiPolicy object to convert.</param>
	/// <returns>bytes array</returns>
	internal static byte[] ConvertXMLToBinary(SiPolicy policyObj)
	{
		using MemoryStream honeyStream = new();
		BinaryOpsForward.ConvertPolicyToBinary(policyObj, honeyStream);
		return honeyStream.ToArray();
	}

	/// <summary>
	/// Saves the SiPolicy object to a XML file.
	/// Uses custom hand made serialization logic that is compatible with Native AOT compilation
	/// </summary>
	/// <param name="policy"></param>
	/// <param name="filePath"></param>
	internal static void SavePolicyToFile(SiPolicy policy, string filePath)
	{
		XmlDocument xmlObj = CustomSerialization.CreateXmlFromSiPolicy(policy);
		xmlObj.Save(filePath);
		CiPolicyTest.TestCiPolicy(filePath);
	}

	// For Unit testing

#if DEBUG

	/// <summary>
	/// Verifies every SiPolicy XML file in a directory by using the existing XML validation,
	/// custom XML deserialization, XML to CIP conversion, CIP to XML conversion, custom XML serialization,
	/// and stable CIP regeneration logic. A temporary working directory is created and deleted automatically.
	/// </summary>
	/// <param name="policyDirectoryPath">Directory that contains SiPolicy XML files.</param>
	internal static void VerifyPolicyXmlDirectory(string policyDirectoryPath)
	{
		string temporaryDirectoryPath = Path.Combine(Path.GetTempPath(), $"SiPolicyXmlVerification_{Guid.NewGuid():N}");

		try
		{
			_ = Directory.CreateDirectory(temporaryDirectoryPath);

			foreach (string policyXmlFile in (FileUtility.GetFilesFast([policyDirectoryPath], null, [".xml"])).Item1)
			{
				VerifyPolicyXmlRoundTrip(policyXmlFile, temporaryDirectoryPath);
			}
		}
		finally
		{
			if (Directory.Exists(temporaryDirectoryPath))
			{
				Directory.Delete(temporaryDirectoryPath, true);
			}
		}
	}

	/// <summary>
	/// Verifies XML validation, custom XML deserialization, XML to CIP conversion, CIP to XML conversion,
	/// round-trip XML validation, and stable canonical CIP regeneration for one policy XML file.
	/// </summary>
	/// <param name="policyXmlPath">Policy XML file to verify.</param>
	/// <param name="temporaryDirectoryPath">Temporary directory where verification artifacts are written.</param>
	private static void VerifyPolicyXmlRoundTrip(string policyXmlPath, string temporaryDirectoryPath)
	{
		string policyName = Path.GetFileNameWithoutExtension(policyXmlPath);
		string firstBinaryPath = Path.Combine(temporaryDirectoryPath, $"{policyName}.First.cip");
		string secondBinaryPath = Path.Combine(temporaryDirectoryPath, $"{policyName}.Second.cip");
		string firstRoundTripXmlPath = Path.Combine(temporaryDirectoryPath, $"{policyName}.RoundTrip.xml");
		string secondRoundTripXmlPath = Path.Combine(temporaryDirectoryPath, $"{policyName}.RoundTrip.FixedPoint.xml");

		CiPolicyTest.TestCiPolicy(policyXmlPath);

		SiPolicy firstPolicy = CustomDeserialization.DeserializeSiPolicy(policyXmlPath, null);
		byte[] firstBinary = ConvertXMLToBinary(firstPolicy);
		File.WriteAllBytes(firstBinaryPath, firstBinary);

		SiPolicy firstReversedPolicy = BinaryOpsReverse.ConvertBinaryToXmlFile(firstBinaryPath);
		XmlDocument firstRoundTripXml = CustomSerialization.CreateXmlFromSiPolicy(firstReversedPolicy);
		firstRoundTripXml.Save(firstRoundTripXmlPath);
		CiPolicyTest.TestCiPolicy(firstRoundTripXmlPath);

		SiPolicy secondPolicy = CustomDeserialization.DeserializeSiPolicy(firstRoundTripXmlPath, null);
		byte[] secondBinary = ConvertXMLToBinary(secondPolicy);
		File.WriteAllBytes(secondBinaryPath, secondBinary);

		SiPolicy secondReversedPolicy = BinaryOpsReverse.ConvertBinaryToXmlFile(secondBinaryPath);
		XmlDocument secondRoundTripXml = CustomSerialization.CreateXmlFromSiPolicy(secondReversedPolicy);
		secondRoundTripXml.Save(secondRoundTripXmlPath);
		CiPolicyTest.TestCiPolicy(secondRoundTripXmlPath);

		SiPolicy thirdPolicy = CustomDeserialization.DeserializeSiPolicy(secondRoundTripXmlPath, null);
		byte[] thirdBinary = ConvertXMLToBinary(thirdPolicy);

		if (secondBinary.Length != thirdBinary.Length)
		{
			throw new InvalidOperationException($"The policy '{policyName}' failed canonical binary stability verification because the binary lengths differ. Second: {secondBinary.Length}, third: {thirdBinary.Length}.");
		}

		for (int index = 0; index < secondBinary.Length; index++)
		{
			if (secondBinary[index] != thirdBinary[index])
			{
				throw new InvalidOperationException($"The policy '{policyName}' failed canonical binary stability verification at byte offset {index}.");
			}
		}
	}

#endif

}
