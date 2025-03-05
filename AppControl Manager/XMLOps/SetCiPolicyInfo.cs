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

using System;
using System.Collections.Generic;
using AppControlManager.Others;

namespace AppControlManager.XMLOps;

internal static class SetCiPolicyInfo
{
	/// <summary>
	/// Configures a XML Code Integrity policy by modifying its details.
	/// When it comes to PolicyID, the only time it is modified is through random GUID generation.
	/// The BasePolicyID however can be modified by supplying a XML file, or providing the GUID directory, or through GUID random generation.
	/// If the policy doesn't have a <Settings> node with a <Setting> node inside of it for PolicyName, it will be created. This is regardless of whether the policyName parameter was provided or not.
	/// </summary>
	/// <param name="filePath">Path to the XML policy file to modify</param>
	///
	/// <param name="resetPolicyID">
	/// Will assign a random GUID for the PolicyID and BasePolicyID of the selected XML file.
	/// If this parameter is specified along with basePolicyID, first both policyID and BasePolicyID will reset and then basePolicyID will be applied to the policy.
	/// Which is the same behavior as Set-CIPolicyIdInfo cmdlet.
	/// </param>
	///
	/// <param name="policyName">The policy name to set for the selected XML policy file</param>
	///
	/// <param name="basePolicyID">
	/// The BasePolicyID to set for the selected XML policy file.
	/// It doesn't need to have curly brackets. They will be added automatically by the method.
	/// It is the same as the -SupplementsBasePolicyID parameter of the Set-CIPolicyIdInfo cmdlet.
	/// It will change the type of the policy to a Supplemental Policy type.
	/// </param>
	///
	/// <param name="basePolicyToSupplementPath">
	/// The path to a XML file. The PolicyID of the file will be extracted and applied to the BasePolicyID of the XML file selected in the filePath parameter.
	/// </param>
	///
	/// <returns> Returns the final policy ID of the XML policy. It will have curly brackets. </returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static string Set(string filePath, bool? resetPolicyID, string? policyName, string? basePolicyID, string? basePolicyToSupplementPath)
	{

		// Instantiate the policy
		SiPolicy.SiPolicy policyObj = SiPolicy.Management.Initialize(filePath, null);

		#region PolicyName Processing

		if (!string.IsNullOrEmpty(policyName))
		{

			bool nameSettingFound = false;

			foreach (SiPolicy.Setting item in policyObj.Settings)
			{
				if (string.Equals(item.ValueName, "Name", StringComparison.OrdinalIgnoreCase))
				{
					item.Value.Item = policyName;

					nameSettingFound = true;
				}
			}

			// If the Setting node with ValueName="Name" does not exist, create it
			if (!nameSettingFound)
			{
				SiPolicy.Setting newNameSetting = new()
				{
					Provider = "PolicyInfo",
					Key = "Information",
					ValueName = "Name",
					Value = new SiPolicy.SettingValueType()
					{
						Item = policyName
					}
				};

				List<SiPolicy.Setting> settings = [.. policyObj.Settings];
				settings.Add(newNameSetting);
				policyObj.Settings = [.. settings];
			}
		}

		#endregion

		#region resetPolicyID processing

		// If the resetPolicyID is true, then assign a new GUID to the PolicyID and BasePolicyID
		if (resetPolicyID == true)
		{
			// Generate a new GUID
			Guid newRandomGUID = Guid.CreateVersion7();

			// Convert it to string
			string newRandomGUIDString = $"{{{newRandomGUID.ToString().ToUpperInvariant()}}}";

			policyObj.BasePolicyID = newRandomGUIDString;
			policyObj.PolicyID = newRandomGUIDString;
		}

		#endregion

		#region basePolicyID processing

		if (!string.IsNullOrWhiteSpace(basePolicyID))
		{

			basePolicyID = basePolicyID.Trim('{', '}');

			// Make sure the input parameter is a valid GUID, doesn't need to have curly brackets, just a GUID string with correct length and format
			if (!Guid.TryParse(basePolicyID, out _))
			{
				throw new ArgumentException($"The provided string '{basePolicyID}' is not a valid GUID format.");
			}

			string tempVar = $"{{{basePolicyID.ToUpperInvariant()}}}";

			// Set the BasePolicyID of the policy file to the user provided one
			policyObj.BasePolicyID = tempVar;
		}

		#endregion

		#region basePolicyToSupplementPath processing

		if (!string.IsNullOrWhiteSpace(basePolicyToSupplementPath))
		{
			SiPolicy.SiPolicy policyObj2 = SiPolicy.Management.Initialize(basePolicyToSupplementPath, null);
			policyObj.BasePolicyID = policyObj2.PolicyID;
		}

		#endregion

		#region Checking Policy Type

		if (policyObj.PolicyType is SiPolicy.PolicyType.SupplementalPolicy)
		{
			if (string.Equals(policyObj.PolicyID, policyObj.BasePolicyID, StringComparison.OrdinalIgnoreCase))
			{
				Logger.Write("The selected XML policy file is a Supplemental policy but its BasePolicyID and PolicyID are the same, indicating it is a Base policy, changing the type.");

				policyObj.PolicyType = SiPolicy.PolicyType.BasePolicy;
			}
		}

		if (policyObj.PolicyType is SiPolicy.PolicyType.BasePolicy)
		{
			if (!string.Equals(policyObj.PolicyID, policyObj.BasePolicyID, StringComparison.OrdinalIgnoreCase))
			{
				Logger.Write("The selected XML policy file is a Base policy but its BasePolicyID and PolicyID are not the same, indicating it is a Supplemental policy, changing the type.");


				policyObj.PolicyType = SiPolicy.PolicyType.SupplementalPolicy;
			}
		}

		#endregion

		// Save the changes to the XML file
		SiPolicy.Management.SavePolicyToFile(policyObj, filePath);

		Logger.Write($"Successfully configured the policy at '{filePath}'. Now it has the Type '{policyObj.PolicyType}', BasePolicyID '{policyObj.BasePolicyID}' and PolicyID '{policyObj.PolicyID}'.");

		return policyObj.PolicyID;
	}


	/// <summary>
	/// An overload of the Set method, responsible for setting the version number, policyID and BasePolicyID in the policy
	/// </summary>
	/// <param name="filePath"></param>
	/// <param name="version"></param>
	/// <param name="ID">This will be used as the BasePolicyID and PolicyID of the policy</param>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void Set(string filePath, Version version, string? ID = null)
	{

		// Instantiate the policy
		SiPolicy.SiPolicy policyObj = SiPolicy.Management.Initialize(filePath, null);

		// save the current XML policy version to a variable prior to modifying it
		string OriginalXMLPolicyVersion = policyObj.VersionEx;

		// Set the user provided version to the policy
		policyObj.VersionEx = version.ToString();

		// If the ID parameter was provided
		if (ID is not null)
		{
			string AdjustedID = ID.Trim('{', '}');

			// Make sure the input parameter is a valid GUID, doesn't need to have curly brackets, just a GUID string with correct length and format
			if (!Guid.TryParse(AdjustedID, out _))
			{
				throw new ArgumentException($"The provided string '{AdjustedID}' is not a valid GUID format.");
			}

			string tempVar = $"{{{AdjustedID.ToUpperInvariant()}}}";

			// Set the BasePolicyID of the policy file to the user provided one
			policyObj.BasePolicyID = tempVar;

			// Set the PolicyID of the policy file to the user provided one
			policyObj.PolicyID = tempVar;
		}

		// Save the changes to the XML file
		SiPolicy.Management.SavePolicyToFile(policyObj, filePath);

		Logger.Write($"Successfully set the version of the policy file at '{filePath}' from '{OriginalXMLPolicyVersion}' to '{version}'.");
	}

}
