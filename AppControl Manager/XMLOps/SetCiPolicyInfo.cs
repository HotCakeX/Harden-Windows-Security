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

namespace AppControlManager.XMLOps;

internal static class SetCiPolicyInfo
{
	/// <summary>
	/// Configures an XML Code Integrity policy by modifying its details.
	/// When it comes to PolicyID, the only time it is modified is through random GUID generation.
	/// The BasePolicyID, however, can be modified by supplying an XML file, providing the GUID directory, or through GUID random generation.
	/// If the policy doesn't have a "Settings" node with a "Setting" node inside it for PolicyName, it will be created. This is regardless of whether the policyName parameter was provided or not.
	/// </summary>
	/// <param name="filePath">Path to the XML policy file to modify.</param>
	/// <param name="resetPolicyID">
	/// Will assign a random GUID for the PolicyID and BasePolicyID of the selected XML file.
	/// If this parameter is specified along with basePolicyID, first both PolicyID and BasePolicyID will reset and then basePolicyID will be applied to the policy.
	/// </param>
	/// <param name="policyName">The policy name to set for the selected XML policy file.</param>
	/// <param name="basePolicyID">
	/// The BasePolicyID to set for the selected XML policy file.
	/// It doesn't need to have curly brackets; they will be added automatically by the method.
	/// This is the same as the -SupplementsBasePolicyID parameter of the Set-CIPolicyIdInfo cmdlet.
	/// It will change the type of the policy to a Supplemental Policy type.
	/// </param>
	/// <param name="basePolicyToSupplementPath">
	/// The path to an XML file. The PolicyID of the file will be extracted and applied to the BasePolicyID of the XML file selected in the filePath parameter.
	/// </param>
	/// <returns>
	/// Returns the final policy ID of the XML policy. It will have curly brackets.
	/// </returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static string Set(string filePath, bool? resetPolicyID, string? policyName, string? basePolicyID, string? basePolicyToSupplementPath)
	{

		// Instantiate the policy
		SiPolicy.SiPolicy policyObj = SiPolicy.Management.Initialize(filePath, null);

		#region PolicyName Processing

		PolicySettingsManager.SetPolicyName(policyObj, policyName);

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
			(bool, string) response = ValidatePolicyID(basePolicyID);

			if (!response.Item1)
			{
				throw new ArgumentException(string.Format(GlobalVars.GetStr("InvalidGuidFormatError"), basePolicyID));
			}

			// Set the BasePolicyID of the policy file to the user provided one
			policyObj.BasePolicyID = response.Item2;
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
				Logger.Write(GlobalVars.GetStr("SupplementalPolicyTypeChangeMessage"));

				policyObj.PolicyType = SiPolicy.PolicyType.BasePolicy;
			}
		}

		if (policyObj.PolicyType is SiPolicy.PolicyType.BasePolicy)
		{
			if (!string.Equals(policyObj.PolicyID, policyObj.BasePolicyID, StringComparison.OrdinalIgnoreCase))
			{
				Logger.Write(GlobalVars.GetStr("BasePolicyTypeChangeMessage"));


				policyObj.PolicyType = SiPolicy.PolicyType.SupplementalPolicy;
			}
		}

		#endregion

		// Save the changes to the XML file
		SiPolicy.Management.SavePolicyToFile(policyObj, filePath);

		Logger.Write(string.Format(GlobalVars.GetStr("PolicyConfigurationSuccessMessage"), filePath, policyObj.PolicyType, policyObj.BasePolicyID, policyObj.PolicyID));

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
			(bool, string) response = ValidatePolicyID(ID);

			if (!response.Item1)
			{
				throw new ArgumentException(string.Format(GlobalVars.GetStr("InvalidGuidFormatError"), ID));
			}

			// Set the BasePolicyID of the policy file to the user provided one
			policyObj.BasePolicyID = response.Item2;

			// Set the PolicyID of the policy file to the user provided one
			policyObj.PolicyID = response.Item2;
		}

		// Save the changes to the XML file
		SiPolicy.Management.SavePolicyToFile(policyObj, filePath);

		Logger.Write(string.Format(GlobalVars.GetStr("PolicyVersionSetSuccessMessage"), filePath, OriginalXMLPolicyVersion, version));
	}


	/// <summary>
	/// A method that accepts a string and tests if it is valid to be a Policy ID or Base Policy ID
	/// </summary>
	/// <param name="id">the string to verify. Having Curly brackets isn't necessary as the method will add them automatically.</param>
	/// <returns>Returns a tuple with 2 items.
	/// First item is a bool indicating the string is valid.
	/// The 2nd item includes the string that can be used in the policy.</returns>
	internal static (bool, string) ValidatePolicyID(string? id)
	{

		if (string.IsNullOrWhiteSpace(id))
		{
			return (false, string.Empty);
		}

		string AdjustedID = id.Trim('{', '}');

		bool IsValid;

		// Make sure the input parameter is a valid GUID, doesn't need to have curly brackets, just a GUID string with correct length and format
		IsValid = Guid.TryParse(AdjustedID, out _);

		string tempVar = $"{{{AdjustedID.ToUpperInvariant()}}}";

		return (IsValid, tempVar);
	}

}
