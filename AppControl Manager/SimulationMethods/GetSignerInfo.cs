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

using System.Collections.Frozen;
using System.Collections.Generic;
using System.Linq;
using System.Xml;
using AppControlManager.Others;
using AppControlManager.SiPolicy;

namespace AppControlManager.SimulationMethods;

internal static class GetSignerInfo
{

	/// <summary>
	/// Well-known IDs for replacing root certificate values
	/// </summary>
	private static readonly FrozenSet<string> wellKnownIDs = FrozenSet.ToFrozenSet(
		new[]
			{
				"03", "04", "05", "06", "07", "09", "0A", "0E", "0G", "0H", "0I"
			}, StringComparer.OrdinalIgnoreCase
	);

	/// <summary>
	/// WHQL EKU Hex value
	/// </summary>
	private const string WHQLEkuHex = "010A2B0601040182370A0305";

	/// <summary>
	/// Takes an XML policy content as input and returns an array of Signer objects
	/// The output contains as much info as possible about each signer
	/// </summary>
	/// <param name="xmlContent"></param>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static List<SignerX> Get(XmlDocument xmlContent)
	{
		// Instantiate the policy
		SiPolicy.SiPolicy policyObj = Management.Initialize(null, xmlContent);

		SigningScenario? UMCI = policyObj.SigningScenarios.FirstOrDefault(x => Equals(x.Value, (byte)12));
		SigningScenario? KMCI = policyObj.SigningScenarios.FirstOrDefault(x => Equals(x.Value, (byte)131));

		HashSet<string> allowedUMCISigners = [];
		HashSet<string> deniedUMCISigners = [];
		HashSet<string> allowedKMCISigners = [];
		HashSet<string> deniedKMCISigners = [];

		if (UMCI is not null)
		{
			if (UMCI.ProductSigners is not null)
			{
				if (UMCI.ProductSigners.AllowedSigners is not null)
				{
					if (UMCI.ProductSigners.AllowedSigners.AllowedSigner is not null)
					{
						foreach (AllowedSigner item in UMCI.ProductSigners.AllowedSigners.AllowedSigner)
						{
							_ = allowedUMCISigners.Add(item.SignerId);
						}
					}
				}
				if (UMCI.ProductSigners.DeniedSigners is not null)
				{
					if (UMCI.ProductSigners.DeniedSigners.DeniedSigner is not null)
					{
						foreach (DeniedSigner item in UMCI.ProductSigners.DeniedSigners.DeniedSigner)
						{
							_ = deniedUMCISigners.Add(item.SignerId);
						}
					}
				}
			}
		}
		if (KMCI is not null)
		{
			if (KMCI.ProductSigners is not null)
			{
				if (KMCI.ProductSigners.AllowedSigners is not null)
				{
					if (KMCI.ProductSigners.AllowedSigners.AllowedSigner is not null)
					{
						foreach (AllowedSigner item in KMCI.ProductSigners.AllowedSigners.AllowedSigner)
						{
							_ = allowedKMCISigners.Add(item.SignerId);
						}
					}
				}
				if (KMCI.ProductSigners.DeniedSigners is not null)
				{
					if (KMCI.ProductSigners.DeniedSigners.DeniedSigner is not null)
					{
						foreach (DeniedSigner item in KMCI.ProductSigners.DeniedSigners.DeniedSigner)
						{
							_ = deniedKMCISigners.Add(item.SignerId);
						}
					}
				}
			}
		}

		// Unique IDs of all Allowed Signers
		HashSet<string> allAllowedSigners = new(allowedUMCISigners, StringComparer.OrdinalIgnoreCase);
		allAllowedSigners.UnionWith(allowedKMCISigners);

		// Unique IDs of all Denied Signers
		HashSet<string> allDeniedSigners = new(deniedUMCISigners, StringComparer.OrdinalIgnoreCase);
		allDeniedSigners.UnionWith(deniedKMCISigners);

		// An empty list to store the output
		List<SignerX> output = [];


		#region
		// Storing all the FileAttribs in a list
		IEnumerable<FileAttrib> fileAttributes = policyObj.FileRules.OfType<FileAttrib>();

		// Dictionary to store the FileAttrib(s) by their ID for fast lookups
		// It's created only once and used by all signers in the XML file
		Dictionary<string, FileAttrib> fileAttribDictionary = [];

		// Populate the dictionary with FileAttrib nodes, using their ID as the key
		foreach (FileAttrib fileAttrib in fileAttributes)
		{
			fileAttribDictionary[fileAttrib.ID] = fileAttrib;
		}
		#endregion


		#region

		// A dictionary to store the correlation between the EKU IDs and their values
		// Keys are EKU IDs
		// Values are EKU values
		Dictionary<string, string> EKUAndValuesCorrelation = [];

		// Add the EKU IDs and their values to the dictionary
		foreach (EKU Eku in policyObj.EKUs)
		{
			EKUAndValuesCorrelation.Add(Eku.ID, CustomSerialization.ConvertByteArrayToHex(Eku.Value));
		}

		#endregion

		// Loop through each Signer node and extract all of their information
		foreach (Signer signer in policyObj.Signers)
		{

			// Determine if the signer is Allowed or Denied
			bool isAllowed;
			if (allAllowedSigners.Contains(signer.ID))
			{
				isAllowed = true;
			}
			else if (allDeniedSigners.Contains(signer.ID))
			{
				isAllowed = false;
			}
			else
			{
				// Skip if the current signer is neither an allowed nor a denied signer, meaning it can either be UpdatePolicySigner or SupplementalPolicySigner which we don't need for simulation
				continue;
			}

			// Replacing Wellknown root IDs with their corresponding TBS values and Names (Common Names)
			// These are all root certificates, they have no leaf or intermediate certificates in their chains, that's why they're called Trusted Roots

			// Get the CertRoot node of the current Signer
			string? certRootValue = CustomSerialization.ConvertByteArrayToHex(signer.CertRoot.Value);

			if (certRootValue is not null && wellKnownIDs.Contains(certRootValue))
			{
				switch (certRootValue)
				{
					case "03":
						certRootValue = "D67576F5521D1CCAB52E9215E0F9F743";
						signer.Name = "Microsoft Authenticode(tm) Root Authority";
						break;
					case "04":
						certRootValue = "8B3C3087B7056F5EC5DDBA91A1B901F0";
						signer.Name = "Microsoft Root Authority";
						break;
					case "05":
						certRootValue = "391BE92883D52509155BFEAE27B9BD340170B76B";
						signer.Name = "Microsoft Root Certificate Authority";
						break;
					case "06":
						certRootValue = "08FBA831C08544208F5208686B991CA1B2CFC510E7301784DDF1EB5BF0393239";
						signer.Name = "Microsoft Root Certificate Authority 2010";
						break;
					case "07":
						certRootValue = "279CD652C4E252BFBE5217AC722205D7729BA409148CFA9E6D9E5B1CB94EAFF1";
						signer.Name = "Microsoft Root Certificate Authority 2011";
						break;
					case "09":
						certRootValue = "09CBAFBD98E81B4D6BAAAB32B8B2F5D7";
						signer.Name = "Microsoft Test Root Authority";
						break;
					case "0A":
						certRootValue = "7A4D9890B0F9006A6F77472D50D83CA54975FCC2B7EA0563490134E19B78782A";
						signer.Name = "Microsoft Testing Root Certificate Authority 2010";
						break;
					case "0E":
						certRootValue = "ED55F82E1444F79CA9DCE826846FDC4E0EA3859E3D26EFEF412D2FFF0C7C8E6C";
						signer.Name = "Microsoft Development Root Certificate Authority 2014";
						break;
					case "0G":
						certRootValue = "68D221D720E975DB5CD14B24F2970F86A5B8605A2A1BC784A17B83F7CF500A70EB177CE228273B8540A800178F23EAC8";
						signer.Name = "Microsoft ECC Testing Root Certificate Authority 2017";
						break;
					case "0H":
						certRootValue = "214592CB01B59104195F80AF2886DBF85771AF42A3821D104BF18F415158C49CBC233511672CD6C432351AC9228E3E75";
						signer.Name = "Microsoft ECC Development Root Certificate Authority 2018";
						break;
					case "0I":
						certRootValue = "32991981BF1575A1A5303BB93A381723EA346B9EC130FDB596A75BA1D7CE0B0A06570BB985D25841E23BE944E8FF118F";
						signer.Name = "Microsoft ECC Product Root Certificate Authority 2018";
						break;
					default:
						break;
				}
			}

			// Determine the scope of the signer
			string signerScope = allowedUMCISigners.Contains(signer.ID) ? "UserMode" : "KernelMode";

			// Find all the FileAttribRef nodes within the current signer
			List<string> ruleIds = [];

			// Extract the RuleID of all of the FileAttribRef nodes
			if (signer.FileAttribRef is not null)
			{
				foreach (FileAttribRef FileAttribRefNode in signer.FileAttribRef)
				{
					ruleIds.Add(FileAttribRefNode.RuleID);
				}
			}

			#region Region File Attributes Processing

			// The File Attributes property that will be added to the Signer object
			// It contains details of all File Attributes associated with the Signer
			Dictionary<string, Dictionary<string, string>> SignerFileAttributesProperty = [];

			// Determine whether the signer has a FileAttribRef, if it points to a file
			if (ruleIds.Count > 0)
			{

				// Create a list to store matching file attributes
				List<FileAttrib> FileAttribsAssociatedWithTheSigner = [];

				// Iterate through the rule IDs and find matching FileAttrib nodes in the dictionary that holds the FileAttrib nodes in the <FileRules> node
				// Get all the FileAttribs associated with the signer
				foreach (string id in ruleIds)
				{
					if (fileAttribDictionary.TryGetValue(id, out FileAttrib? matchingFileAttrib))
					{
						FileAttribsAssociatedWithTheSigner.Add(matchingFileAttrib);
					}
				}


				// Loop over each FileAttribute associated with the Signer
				foreach (FileAttrib item in FileAttribsAssociatedWithTheSigner)
				{

					// a temp dictionary to store the current FileAttribute details
					Dictionary<string, string> temp = [];

					string? FileName = item.FileName;
					string? FileDescription = item.FileDescription;
					string? InternalName = item.InternalName;
					string? ProductName = item.ProductName;

					if (FileName is not null)
					{
						temp.Add("OriginalFileName", FileName);
						temp.Add("SpecificFileNameLevel", "OriginalFileName");
					}
					else if (FileDescription is not null)
					{
						temp.Add("FileDescription", FileDescription);
						temp.Add("SpecificFileNameLevel", "FileDescription");
					}
					else if (InternalName is not null)
					{
						temp.Add("InternalName", InternalName);
						temp.Add("SpecificFileNameLevel", "InternalName");
					}
					else if (ProductName is not null)
					{
						temp.Add("ProductName", ProductName);
						temp.Add("SpecificFileNameLevel", "ProductName");
					}

					string? MinimumFileVersion = item.MinimumFileVersion;
					string? MaximumFileVersion = item.MaximumFileVersion;

					if (MinimumFileVersion is not null)
					{
						temp.Add("MinimumFileVersion", MinimumFileVersion);
					}

					if (MaximumFileVersion is not null)
					{
						temp.Add("MaximumFileVersion", MaximumFileVersion);
					}

					SignerFileAttributesProperty.Add(item.ID, temp);

				}

			}

			#endregion


			#region Region EKU Processing

			bool HasEKU = false;
			bool IsWHQL = false;

			// Convert all of the EKUs that apply to the signer to their OID values and store them with the Signer info

			// This list stores only the IDs of the EKUs
			List<string> CertEKUIDs = [];

			// This list stores the OID of the current signer's EKUs
			List<string> CertEKUs = [];

			// Select all of the <CertEKU> nodes in the current signer
			if (signer.CertEKU is not null)
			{
				foreach (CertEKU EKU in signer.CertEKU)
				{
					CertEKUIDs.Add(EKU.ID);
				}
			}

			foreach (string EkuID in CertEKUIDs)
			{
				_ = EKUAndValuesCorrelation.TryGetValue(EkuID, out string? EkuValue);

				if (EkuValue is not null)
				{
					// Check if the current EKU of the signer is WHQL
					if (string.Equals(EkuValue, WHQLEkuHex, StringComparison.OrdinalIgnoreCase))
					{
						IsWHQL = true;
					}

					// The signer has at least one EKU, so set this to true
					HasEKU = true;

					CertEKUs.Add(CertificateHelper.ConvertHexToOID(EkuValue));
				}
			}

			#endregion

			// Add the current signer's info to the output array
			output.Add(
				new SignerX(
				   id: signer.ID,
					name: signer.Name,
					certRoot: certRootValue!,
					certPublisher: signer.CertPublisher?.Value,
					certIssuer: signer.CertIssuer?.Value,
					certEKU: [.. CertEKUs],
					certOemID: signer.CertOemID?.Value,
					fileAttribRef: [.. ruleIds],
					fileAttrib: SignerFileAttributesProperty,
					signerScope: signerScope,
					isWHQL: IsWHQL,
					isAllowed: isAllowed,
					hasEKU: HasEKU
					)
				);
		}

		return output;
	}
}
