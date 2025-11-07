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
using AppControlManager.SiPolicy;
using AppControlManager.XMLOps;

namespace AppControlManager.Main;

internal static class CiRuleOptions
{

	internal enum PolicyTemplate
	{
		Base,
		BaseISG,
		BaseKernel,
		Supplemental
	}

	#region Defining the rule options for each policy type and scenario

	private static readonly FrozenSet<OptionType> BaseRules = new HashSet<OptionType>
	{
		OptionType.EnabledUMCI,
		OptionType.RequiredWHQL,
		OptionType.EnabledInheritDefaultPolicy,
		OptionType.EnabledUnsignedSystemIntegrityPolicy,
		OptionType.DisabledScriptEnforcement,
		OptionType.RequiredEnforceStoreApplications,
		OptionType.EnabledUpdatePolicyNoReboot,
		OptionType.EnabledAllowSupplementalPolicies,
		OptionType.EnabledDynamicCodeSecurity,
		OptionType.EnabledRevokedExpiredAsUnsigned
	}.ToFrozenSet();

	private static readonly FrozenSet<OptionType> BaseISGRules = new HashSet<OptionType>
	{
		OptionType.EnabledUMCI,
		OptionType.RequiredWHQL,
		OptionType.EnabledInheritDefaultPolicy,
		OptionType.EnabledUnsignedSystemIntegrityPolicy,
		OptionType.DisabledScriptEnforcement,
		OptionType.RequiredEnforceStoreApplications,
		OptionType.EnabledIntelligentSecurityGraphAuthorization,
		OptionType.EnabledInvalidateEAsonReboot,
		OptionType.EnabledUpdatePolicyNoReboot,
		OptionType.EnabledAllowSupplementalPolicies,
		OptionType.EnabledDynamicCodeSecurity,
		OptionType.EnabledRevokedExpiredAsUnsigned
	}.ToFrozenSet();

	private static readonly FrozenSet<OptionType> BaseKernelModeRules = new HashSet<OptionType>
	{
		OptionType.RequiredWHQL,
		OptionType.EnabledInheritDefaultPolicy,
		OptionType.EnabledUnsignedSystemIntegrityPolicy,
		OptionType.EnabledUpdatePolicyNoReboot,
		OptionType.EnabledAllowSupplementalPolicies,
		OptionType.EnabledRevokedExpiredAsUnsigned
	}.ToFrozenSet();

	private static readonly HashSet<OptionType> SupplementalRules = [
		OptionType.EnabledUnsignedSystemIntegrityPolicy
          // OptionType.DisabledRuntimeFilePathRuleProtection - Only add this if the Supplemental policy will have FilePath rules and user explicitly asks for allowing user-writable file paths
        ];

	private static readonly HashSet<OptionType> RequireWHQLRules = [OptionType.RequiredWHQL];
	private static readonly HashSet<OptionType> EnableAuditModeRules = [OptionType.EnabledAuditMode];
	private static readonly HashSet<OptionType> DisableFlightSigningRules = [OptionType.DisabledFlightSigning];
	private static readonly HashSet<OptionType> RequireEVSignersRules = [OptionType.RequiredEVSigners];
	private static readonly HashSet<OptionType> ScriptEnforcementRules = [OptionType.DisabledScriptEnforcement];
	private static readonly HashSet<OptionType> TestModeRules = [OptionType.EnabledAdvancedBootOptionsMenu, OptionType.EnabledBootAuditOnFailure];
	#endregion


	private static readonly HashSet<OptionType> SupplementalPolicyAllowedRuleOptions = [
		OptionType.DisabledRuntimeFilePathRuleProtection,
		OptionType.EnabledIntelligentSecurityGraphAuthorization,
		OptionType.EnabledManagedInstaller,
		OptionType.EnabledInheritDefaultPolicy,
		OptionType.EnabledUnsignedSystemIntegrityPolicy
		];

	/// <summary>
	/// Configures the Policy rule options in a given XML file and sets the HVCI to Strict in the output XML file.
	/// It offers many ways to configure the policy rule options in a given XML file.
	/// All of its various parameters provide the flexibility that ensures only one pass is needed to configure the policy rule options.
	/// First the template is processed, then the individual boolean parameters, and finally the individual rules to add and remove.
	/// </summary>
	/// <param name="filePath">  Specifies the path to the XML file that contains the CI policy rules </param>
	/// <param name="template"> Specifies the template to use for the CI policy rules </param>
	/// <param name="rulesToAdd"> Specifies the rule options to add to the policy XML file </param>
	/// <param name="rulesToRemove">  Specifies the rule options to remove from the policy XML file </param>
	/// <param name="RequireWHQL"> Specifies whether to require WHQL signatures for all drivers </param>
	/// <param name="EnableAuditMode"> Specifies whether to enable audit mode </param>
	/// <param name="DisableFlightSigning"> Specifies whether to disable flight signing </param>
	/// <param name="RequireEVSigners"> Specifies whether to require EV signers </param>
	/// <param name="ScriptEnforcement"> Specifies whether to disable script enforcement </param>
	/// <param name="TestMode"> Specifies whether to enable test mode </param>
	/// <param name="RemoveAll"> Removes all the existing rule options from the policy XML file </param>
	/// <param name="DirectPolicyObj"> Instead of supplying a policy file, use the de-serialized SiPolicy object. The changes will still be saved to the policy file path that is provided which is a mandatory parameter. </param>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void Set(
		string filePath,
		PolicyTemplate? template = null,
		OptionType[]? rulesToAdd = null,
		OptionType[]? rulesToRemove = null,
		bool? RequireWHQL = null,
		bool? EnableAuditMode = null,
		bool? DisableFlightSigning = null,
		bool? RequireEVSigners = null,
		bool? ScriptEnforcement = null,
		bool? TestMode = null,
		bool? RemoveAll = null,
		SiPolicy.SiPolicy? DirectPolicyObj = null
		)
	{

		Logger.Write(string.Format(
			GlobalVars.GetStr("ConfiguringPolicyRuleOptionsForMessage"),
			filePath));

		// Instantiate the policy or use the supplied SiPolicy object
		SiPolicy.SiPolicy policyObj = DirectPolicyObj ?? Management.Initialize(filePath, null);

		// To store the existing rule options in the XML policy file
		HashSet<OptionType> ExistingRuleOptions = [];

		// The final rule options to implement which contains only unique values
		HashSet<OptionType> RuleOptionsToImplement = [];

		// A flag to determine whether to clear all the existing rules based on the input parameters
		bool ClearAllRules = false;

		if (template is not null || RemoveAll is not null)
		{
			ClearAllRules = true;
		}

		// Store the current policy rules
		if (policyObj.Rules.Length > 0)
		{
			// Iterating through each <Rule> node in the supplied XML file
			foreach (RuleType rule in policyObj.Rules)
			{
				// Add the option text and its corresponding int value to the dictionary
				_ = ExistingRuleOptions.Add(rule.Item);
			}
		}

		if (!ClearAllRules && ExistingRuleOptions.Count > 0)
		{
			// Add the existing rule options to the final rule options to implement
			RuleOptionsToImplement.UnionWith(ExistingRuleOptions);
		}

		// Process selected templates
		switch (template)
		{
			case PolicyTemplate.Base:
				RuleOptionsToImplement.UnionWith(BaseRules);
				break;
			case PolicyTemplate.BaseISG:
				RuleOptionsToImplement.UnionWith(BaseISGRules);
				break;
			case PolicyTemplate.BaseKernel:
				RuleOptionsToImplement.UnionWith(BaseKernelModeRules);
				break;
			case PolicyTemplate.Supplemental:
				RuleOptionsToImplement.UnionWith(SupplementalRules);
				break;
			default:
				break;
		}


		#region Process individual boolean parameters

		// if RequireWHQL is not null and is explicitly set to true
		if (RequireWHQL == true)
		{
			RuleOptionsToImplement.UnionWith(RequireWHQLRules);
		}
		// if RequireWHQL is not null and is explicitly set to false
		if (RequireWHQL == false)
		{
			RuleOptionsToImplement.ExceptWith(RequireWHQLRules);
		}

		// Same logic for the rest, if any of these are null, they are skipped
		if (EnableAuditMode == true)
		{
			RuleOptionsToImplement.UnionWith(EnableAuditModeRules);
		}
		if (EnableAuditMode == false)
		{
			RuleOptionsToImplement.ExceptWith(EnableAuditModeRules);
		}

		if (DisableFlightSigning == true)
		{
			RuleOptionsToImplement.UnionWith(DisableFlightSigningRules);
		}
		if (DisableFlightSigning == false)
		{
			RuleOptionsToImplement.ExceptWith(DisableFlightSigningRules);
		}

		if (RequireEVSigners == true)
		{
			RuleOptionsToImplement.UnionWith(RequireEVSignersRules);
		}
		if (RequireEVSigners == false)
		{
			RuleOptionsToImplement.ExceptWith(RequireEVSignersRules);
		}

		if (ScriptEnforcement == false)
		{
			RuleOptionsToImplement.UnionWith(ScriptEnforcementRules);
		}
		if (ScriptEnforcement == true)
		{
			RuleOptionsToImplement.ExceptWith(ScriptEnforcementRules);
		}

		if (TestMode == true)
		{
			RuleOptionsToImplement.UnionWith(TestModeRules);
		}
		if (TestMode == false)
		{
			RuleOptionsToImplement.ExceptWith(TestModeRules);
		}
		#endregion

		// Process individual rules to add
		if (rulesToAdd is not null)
		{
			foreach (OptionType rule in rulesToAdd)
			{
				_ = RuleOptionsToImplement.Add(rule);
			}
		}

		// Process individual rules to remove
		if (rulesToRemove is not null)
		{
			foreach (OptionType rule in rulesToRemove)
			{
				_ = RuleOptionsToImplement.Remove(rule);
			}
		}

		// Make sure Supplemental policies only contain rule options that are applicable to them
		if (template is PolicyTemplate.Supplemental || policyObj.PolicyType is PolicyType.SupplementalPolicy)
		{
			_ = RuleOptionsToImplement.RemoveWhere(rule => !SupplementalPolicyAllowedRuleOptions.Contains(rule));
		}

		#region Compare the existing rule options in the policy XML file with the rule options to implement

		// Find elements in RuleOptionsToImplement that are not in ExistingRuleOptions
		IEnumerable<OptionType> toAdd = RuleOptionsToImplement.Except(ExistingRuleOptions);

		// Find elements in ExistingRuleOptions that are not in RuleOptionsToImplement
		IEnumerable<OptionType> toRemove = ExistingRuleOptions.Except(RuleOptionsToImplement);

		foreach (OptionType option in toAdd)
		{
			Logger.Write(string.Format(
				GlobalVars.GetStr("AddingRuleOptionMessage"),
				option));
		}
		foreach (OptionType option in toRemove)
		{
			Logger.Write(string.Format(
				GlobalVars.GetStr("RemovingRuleOptionMessage"),
				option));
		}
		#endregion

		List<RuleType> finalRuleToImplement = [];

		// Create new Rules
		foreach (OptionType rule in RuleOptionsToImplement)
		{
			finalRuleToImplement.Add(new RuleType() { Item = rule });
		}

		// Assign the new rules to implement on the policy object, replacing any existing rules
		policyObj.Rules = [.. finalRuleToImplement];

		// Save the XML
		Management.SavePolicyToFile(policyObj, filePath);

		// Set the HVCI to Strict
		UpdateHvciOptions.Update(filePath);
	}
}
