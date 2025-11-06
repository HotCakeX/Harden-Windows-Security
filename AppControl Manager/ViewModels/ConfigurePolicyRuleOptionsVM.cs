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
using System.Linq;
using System.Threading.Tasks;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.SiPolicy;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.ViewModels;

internal sealed partial class ConfigurePolicyRuleOptionsVM : ViewModelBase
{

	internal ConfigurePolicyRuleOptionsVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);
	}

	internal readonly InfoBarSettings MainInfoBar;

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	internal Visibility BrowseForXMLPolicyButtonLightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool SettingsExpanderIsExpanded { get; set => SP(ref field, value); }

	internal bool ElementsAreEnabled { get; set => SP(ref field, value); } = true;

	internal bool DeployAfterApplyingToggleButton { get; set => SP(ref field, value); }

	internal string PolicyTemplatesComboBoxSelectedItem { get; set => SP(ref field, value); } = "Base";

	internal bool AreUnsupportedRuleOptionsEnabled { get; set => SP(ref field, value); }

	/// <summary>
	/// To store the selected policy path
	/// </summary>
	internal string? SelectedFilePath { get; set => SP(ref field, value); }

	#region CheckBox Properties

	internal bool EnabledUMCICheckBox { get; set => SP(ref field, value); }
	internal bool EnabledBootMenuProtectionCheckBox { get; set => SP(ref field, value); }
	internal bool RequiredWHQLCheckBox { get; set => SP(ref field, value); }
	internal bool EnabledAuditModeCheckBox { get; set => SP(ref field, value); }
	internal bool DisabledFlightSigningCheckBox { get; set => SP(ref field, value); }
	internal bool EnabledInheritDefaultPolicyCheckBox { get; set => SP(ref field, value); }
	internal bool EnabledUnsignedSystemIntegrityPolicyCheckBox { get; set => SP(ref field, value); }
	internal bool RequiredEVSignersCheckBox { get; set => SP(ref field, value); }
	internal bool EnabledAdvancedBootOptionsMenuCheckBox { get; set => SP(ref field, value); }
	internal bool EnabledBootAuditOnFailureCheckBox { get; set => SP(ref field, value); }
	internal bool DisabledScriptEnforcementCheckBox { get; set => SP(ref field, value); }
	internal bool RequiredEnforceStoreApplicationsCheckBox { get; set => SP(ref field, value); }
	internal bool EnabledManagedInstallerCheckBox { get; set => SP(ref field, value); }
	internal bool EnabledIntelligentSecurityGraphAuthorizationCheckBox { get; set => SP(ref field, value); }
	internal bool EnabledInvalidateEAsOnRebootCheckBox { get; set => SP(ref field, value); }
	internal bool EnabledUpdatePolicyNoRebootCheckBox { get; set => SP(ref field, value); }
	internal bool EnabledAllowSupplementalPoliciesCheckBox { get; set => SP(ref field, value); }
	internal bool DisabledRuntimeFilePathRuleProtectionCheckBox { get; set => SP(ref field, value); }
	internal bool EnabledDynamicCodeSecurityCheckBox { get; set => SP(ref field, value); }
	internal bool EnabledRevokedExpiredAsUnsignedCheckBox { get; set => SP(ref field, value); }
	internal bool EnabledDeveloperModeDynamicCodeTrustCheckBox { get; set => SP(ref field, value); }
	internal bool EnabledSecureSettingPolicyCheckBox { get; set => SP(ref field, value); }
	internal bool EnabledConditionalWindowsLockdownPolicyCheckBox { get; set => SP(ref field, value); }

	#endregion

	/// <summary>
	/// Event handler for the browse button
	/// </summary>
	internal async void PickPolicyFileButton_Click()
	{
		try
		{
			string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

			if (!string.IsNullOrWhiteSpace(selectedFile))
			{
				SelectedFilePath = selectedFile;

				// Load the policy options from the XML and update the UI
				await LoadPolicyOptionsFromXML();
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// When the XML policy file is selected by the user, get its rule options and check/uncheck the check boxes in the UI accordingly
	/// </summary>
	internal async Task LoadPolicyOptionsFromXML()
	{
		try
		{
			SiPolicy.SiPolicy policyObj = null!;

			await Task.Run(() =>
			{
				policyObj = Management.Initialize(SelectedFilePath, null);
			});

			// All the Policy OptionTypes in the selected XML file
			List<OptionType> policyRules = policyObj.Rules.Select(x => x.Item).ToList();

			// Update each checkbox state based on the policy rules
			EnabledUMCICheckBox = policyRules.Contains(CustomDeserialization.ConvertStringToOptionType("Enabled:UMCI"));
			EnabledBootMenuProtectionCheckBox = policyRules.Contains(CustomDeserialization.ConvertStringToOptionType("Enabled:Boot Menu Protection"));
			RequiredWHQLCheckBox = policyRules.Contains(CustomDeserialization.ConvertStringToOptionType("Required:WHQL"));
			EnabledAuditModeCheckBox = policyRules.Contains(CustomDeserialization.ConvertStringToOptionType("Enabled:Audit Mode"));
			DisabledFlightSigningCheckBox = policyRules.Contains(CustomDeserialization.ConvertStringToOptionType("Disabled:Flight Signing"));
			EnabledInheritDefaultPolicyCheckBox = policyRules.Contains(CustomDeserialization.ConvertStringToOptionType("Enabled:Inherit Default Policy"));
			EnabledUnsignedSystemIntegrityPolicyCheckBox = policyRules.Contains(CustomDeserialization.ConvertStringToOptionType("Enabled:Unsigned System Integrity Policy"));
			RequiredEVSignersCheckBox = policyRules.Contains(CustomDeserialization.ConvertStringToOptionType("Required:EV Signers"));
			EnabledAdvancedBootOptionsMenuCheckBox = policyRules.Contains(CustomDeserialization.ConvertStringToOptionType("Enabled:Advanced Boot Options Menu"));
			EnabledBootAuditOnFailureCheckBox = policyRules.Contains(CustomDeserialization.ConvertStringToOptionType("Enabled:Boot Audit On Failure"));
			DisabledScriptEnforcementCheckBox = policyRules.Contains(CustomDeserialization.ConvertStringToOptionType("Disabled:Script Enforcement"));
			RequiredEnforceStoreApplicationsCheckBox = policyRules.Contains(CustomDeserialization.ConvertStringToOptionType("Required:Enforce Store Applications"));
			EnabledManagedInstallerCheckBox = policyRules.Contains(CustomDeserialization.ConvertStringToOptionType("Enabled:Managed Installer"));
			EnabledIntelligentSecurityGraphAuthorizationCheckBox = policyRules.Contains(CustomDeserialization.ConvertStringToOptionType("Enabled:Intelligent Security Graph Authorization"));
			EnabledInvalidateEAsOnRebootCheckBox = policyRules.Contains(CustomDeserialization.ConvertStringToOptionType("Enabled:Invalidate EAs on Reboot"));
			EnabledUpdatePolicyNoRebootCheckBox = policyRules.Contains(CustomDeserialization.ConvertStringToOptionType("Enabled:Update Policy No Reboot"));
			EnabledAllowSupplementalPoliciesCheckBox = policyRules.Contains(CustomDeserialization.ConvertStringToOptionType("Enabled:Allow Supplemental Policies"));
			DisabledRuntimeFilePathRuleProtectionCheckBox = policyRules.Contains(CustomDeserialization.ConvertStringToOptionType("Disabled:Runtime FilePath Rule Protection"));
			EnabledDynamicCodeSecurityCheckBox = policyRules.Contains(CustomDeserialization.ConvertStringToOptionType("Enabled:Dynamic Code Security"));
			EnabledRevokedExpiredAsUnsignedCheckBox = policyRules.Contains(CustomDeserialization.ConvertStringToOptionType("Enabled:Revoked Expired As Unsigned"));
			EnabledDeveloperModeDynamicCodeTrustCheckBox = policyRules.Contains(CustomDeserialization.ConvertStringToOptionType("Enabled:Developer Mode Dynamic Code Trust"));
			EnabledSecureSettingPolicyCheckBox = policyRules.Contains(CustomDeserialization.ConvertStringToOptionType("Enabled:Secure Setting Policy"));
			EnabledConditionalWindowsLockdownPolicyCheckBox = policyRules.Contains(CustomDeserialization.ConvertStringToOptionType("Enabled:Conditional Windows Lockdown Policy"));

			// Expand the settings expander to display the settings.
			SettingsExpanderIsExpanded = true;
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Event handler for when the Apply button is pressed
	/// </summary>
	internal async void ApplyTheChangesButton_Click()
	{

		try
		{
			ElementsAreEnabled = false;

			if (string.IsNullOrWhiteSpace(SelectedFilePath))
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("SelectPolicyFileBeforeAddingOptions"));
				return;
			}

			// Gather selected rules to add
			OptionType[] selectedOptions = [.. GetSelectedPolicyRuleOptions()];

			await Task.Run(() =>
			{
				CiRuleOptions.Set(SelectedFilePath, rulesToAdd: selectedOptions, RemoveAll: true);
			});

			if (DeployAfterApplyingToggleButton)
			{
				await Task.Run(() =>
				{
					DirectoryInfo stagingArea = StagingArea.NewStagingArea("ConfigurePolicyRuleOptionsDeployment");

					string cipPath = Path.Combine(stagingArea.FullName, $"{Path.GetFileName(SelectedFilePath)}.cip");

					SiPolicy.SiPolicy policyObj = Management.Initialize(SelectedFilePath, null);

					if (!policyObj.Rules.Any(x => x.Item is OptionType.EnabledUnsignedSystemIntegrityPolicy))
					{
						MainInfoBar.WriteWarning(GlobalVars.GetStr("TeachingTipSubtitlePolicyRequiresSigning"));
						return;
					}

					Management.ConvertXMLToBinary(SelectedFilePath, null, cipPath);

					// If a base policy is being deployed, ensure it's supplemental policy for AppControl Manager also gets deployed
					if (SupplementalForSelf.IsEligible(policyObj, SelectedFilePath))
						SupplementalForSelf.Deploy(stagingArea.FullName, policyObj.PolicyID);

					CiToolHelper.UpdatePolicy(cipPath);
				});
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Event handler for the Set button click in the PolicyTemplate section
	/// </summary>
	internal async void SetPolicyTemplate_Click()
	{
		try
		{
			ElementsAreEnabled = false;

			if (string.IsNullOrWhiteSpace(SelectedFilePath))
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("SelectPolicyFileBeforeSettingTemplate"));
				return;
			}

			// Convert the ComboBoxItem content to the corresponding PolicyTemplate enum value
			CiRuleOptions.PolicyTemplate template = Enum.Parse<CiRuleOptions.PolicyTemplate>(PolicyTemplatesComboBoxSelectedItem);

			// Call the Set method with only the filePath and template parameters
			await Task.Run(() =>
			{
				CiRuleOptions.Set(SelectedFilePath, template: template);
			});

			// Refresh the UI check boxes
			await LoadPolicyOptionsFromXML();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Event handler for the flyout's clear button
	/// </summary>
	internal void PickPolicyFileButton_FlyOut_Clear_Click()
	{
		SelectedFilePath = null;
		ClearAllCheckBoxes();
	}

	/// <summary>
	/// Event handlers to retrieve latest policy rule option details from the XML file and check/uncheck UI boxes
	/// </summary>
	internal async void RefreshRuleOptionsState_Click()
	{
		try
		{
			ElementsAreEnabled = false;

			if (SelectedFilePath is not null)
			{
				await LoadPolicyOptionsFromXML();
			}
			else
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("SelectPolicyFileBeforeRetrievingOptions"));
				return;
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}


	/// <summary>
	/// Helper method to get selected policy rule options from the UI checkboxes
	/// </summary>
	/// <returns></returns>
	internal List<OptionType> GetSelectedPolicyRuleOptions()
	{
		List<OptionType> selectedRules = [];

		// Check each checkbox individually
		if (EnabledUMCICheckBox)
			selectedRules.Add(CustomDeserialization.ConvertStringToOptionType("Enabled:UMCI"));
		if (EnabledBootMenuProtectionCheckBox)
			selectedRules.Add(CustomDeserialization.ConvertStringToOptionType("Enabled:Boot Menu Protection"));
		if (RequiredWHQLCheckBox)
			selectedRules.Add(CustomDeserialization.ConvertStringToOptionType("Required:WHQL"));
		if (EnabledAuditModeCheckBox)
			selectedRules.Add(CustomDeserialization.ConvertStringToOptionType("Enabled:Audit Mode"));
		if (DisabledFlightSigningCheckBox)
			selectedRules.Add(CustomDeserialization.ConvertStringToOptionType("Disabled:Flight Signing"));
		if (EnabledInheritDefaultPolicyCheckBox)
			selectedRules.Add(CustomDeserialization.ConvertStringToOptionType("Enabled:Inherit Default Policy"));
		if (EnabledUnsignedSystemIntegrityPolicyCheckBox)
			selectedRules.Add(CustomDeserialization.ConvertStringToOptionType("Enabled:Unsigned System Integrity Policy"));
		if (RequiredEVSignersCheckBox)
			selectedRules.Add(CustomDeserialization.ConvertStringToOptionType("Required:EV Signers"));
		if (EnabledAdvancedBootOptionsMenuCheckBox)
			selectedRules.Add(CustomDeserialization.ConvertStringToOptionType("Enabled:Advanced Boot Options Menu"));
		if (EnabledBootAuditOnFailureCheckBox)
			selectedRules.Add(CustomDeserialization.ConvertStringToOptionType("Enabled:Boot Audit On Failure"));
		if (DisabledScriptEnforcementCheckBox)
			selectedRules.Add(CustomDeserialization.ConvertStringToOptionType("Disabled:Script Enforcement"));
		if (RequiredEnforceStoreApplicationsCheckBox)
			selectedRules.Add(CustomDeserialization.ConvertStringToOptionType("Required:Enforce Store Applications"));
		if (EnabledManagedInstallerCheckBox)
			selectedRules.Add(CustomDeserialization.ConvertStringToOptionType("Enabled:Managed Installer"));
		if (EnabledIntelligentSecurityGraphAuthorizationCheckBox)
			selectedRules.Add(CustomDeserialization.ConvertStringToOptionType("Enabled:Intelligent Security Graph Authorization"));
		if (EnabledInvalidateEAsOnRebootCheckBox)
			selectedRules.Add(CustomDeserialization.ConvertStringToOptionType("Enabled:Invalidate EAs on Reboot"));
		if (EnabledUpdatePolicyNoRebootCheckBox)
			selectedRules.Add(CustomDeserialization.ConvertStringToOptionType("Enabled:Update Policy No Reboot"));
		if (EnabledAllowSupplementalPoliciesCheckBox)
			selectedRules.Add(CustomDeserialization.ConvertStringToOptionType("Enabled:Allow Supplemental Policies"));
		if (DisabledRuntimeFilePathRuleProtectionCheckBox)
			selectedRules.Add(CustomDeserialization.ConvertStringToOptionType("Disabled:Runtime FilePath Rule Protection"));
		if (EnabledDynamicCodeSecurityCheckBox)
			selectedRules.Add(CustomDeserialization.ConvertStringToOptionType("Enabled:Dynamic Code Security"));
		if (EnabledRevokedExpiredAsUnsignedCheckBox)
			selectedRules.Add(CustomDeserialization.ConvertStringToOptionType("Enabled:Revoked Expired As Unsigned"));
		if (EnabledDeveloperModeDynamicCodeTrustCheckBox)
			selectedRules.Add(CustomDeserialization.ConvertStringToOptionType("Enabled:Developer Mode Dynamic Code Trust"));
		if (EnabledSecureSettingPolicyCheckBox)
			selectedRules.Add(CustomDeserialization.ConvertStringToOptionType("Enabled:Secure Setting Policy"));
		if (EnabledConditionalWindowsLockdownPolicyCheckBox)
			selectedRules.Add(CustomDeserialization.ConvertStringToOptionType("Enabled:Conditional Windows Lockdown Policy"));

		return selectedRules;
	}

	/// <summary>
	/// Uncheck all of the rule options check boxes in the UI
	/// </summary>
	internal void ClearAllCheckBoxes()
	{
		EnabledUMCICheckBox = false;
		EnabledBootMenuProtectionCheckBox = false;
		RequiredWHQLCheckBox = false;
		EnabledAuditModeCheckBox = false;
		DisabledFlightSigningCheckBox = false;
		EnabledInheritDefaultPolicyCheckBox = false;
		EnabledUnsignedSystemIntegrityPolicyCheckBox = false;
		RequiredEVSignersCheckBox = false;
		EnabledAdvancedBootOptionsMenuCheckBox = false;
		EnabledBootAuditOnFailureCheckBox = false;
		DisabledScriptEnforcementCheckBox = false;
		RequiredEnforceStoreApplicationsCheckBox = false;
		EnabledManagedInstallerCheckBox = false;
		EnabledIntelligentSecurityGraphAuthorizationCheckBox = false;
		EnabledInvalidateEAsOnRebootCheckBox = false;
		EnabledUpdatePolicyNoRebootCheckBox = false;
		EnabledAllowSupplementalPoliciesCheckBox = false;
		DisabledRuntimeFilePathRuleProtectionCheckBox = false;
		EnabledDynamicCodeSecurityCheckBox = false;
		EnabledRevokedExpiredAsUnsignedCheckBox = false;
		EnabledDeveloperModeDynamicCodeTrustCheckBox = false;
		EnabledSecureSettingPolicyCheckBox = false;
		EnabledConditionalWindowsLockdownPolicyCheckBox = false;
	}

	internal readonly Dictionary<string, string> RuleOptions = new()
	{
		{ "Enabled:UMCI", GlobalVars.GetStr("RuleOption_EnabledUMCI") },
		{ "Enabled:Boot Menu Protection", GlobalVars.GetStr("RuleOption_EnabledBootMenuProtection") },
		{ "Required:WHQL", GlobalVars.GetStr("RuleOption_RequiredWHQL") },
		{ "Enabled:Audit Mode", GlobalVars.GetStr("RuleOption_EnabledAuditMode") },
		{ "Disabled:Flight Signing", GlobalVars.GetStr("RuleOption_DisabledFlightSigning") },
		{ "Enabled:Inherit Default Policy", GlobalVars.GetStr("RuleOption_EnabledInheritDefaultPolicy") },
		{ "Enabled:Unsigned System Integrity Policy", GlobalVars.GetStr("RuleOption_EnabledUnsignedSystemIntegrityPolicy") },
		{ "Required:EV Signers", GlobalVars.GetStr("RuleOption_EnabledBootMenuProtection") },
		{ "Enabled:Advanced Boot Options Menu", GlobalVars.GetStr("RuleOption_EnabledAdvancedBootOptionsMenu") },
		{ "Enabled:Boot Audit On Failure", GlobalVars.GetStr("RuleOption_EnabledBootAuditOnFailure") },
		{ "Disabled:Script Enforcement", GlobalVars.GetStr("RuleOption_DisabledScriptEnforcement") },
		{ "Required:Enforce Store Applications", GlobalVars.GetStr("RuleOption_RequiredEnforceStoreApplications") },
		{ "Enabled:Managed Installer", GlobalVars.GetStr("RuleOption_EnabledManagedInstaller") },
		{ "Enabled:Intelligent Security Graph Authorization", GlobalVars.GetStr("RuleOption_EnabledIntelligentSecurityGraphAuthorization") },
		{ "Enabled:Invalidate EAs on Reboot", GlobalVars.GetStr("RuleOption_EnabledInvalidateEAsOnReboot") },
		{ "Enabled:Update Policy No Reboot", GlobalVars.GetStr("RuleOption_EnabledUpdatePolicyNoReboot") },
		{ "Enabled:Allow Supplemental Policies", GlobalVars.GetStr("RuleOption_EnabledAllowSupplementalPolicies") },
		{ "Disabled:Runtime FilePath Rule Protection", GlobalVars.GetStr("RuleOption_DisabledRuntimeFilePathRuleProtection") },
		{ "Enabled:Dynamic Code Security",GlobalVars.GetStr("RuleOption_EnabledDynamicCodeSecurity") },
		{ "Enabled:Revoked Expired As Unsigned", GlobalVars.GetStr("RuleOption_EnabledRevokedExpiredAsUnsigned") },
		{ "Enabled:Developer Mode Dynamic Code Trust", GlobalVars.GetStr("RuleOption_EnabledDeveloperModeDynamicCodeTrust") },
		{ "Enabled:Secure Setting Policy", GlobalVars.GetStr("RuleOption_EnabledSecureSettingPolicy") },
		{ "Enabled:Conditional Windows Lockdown Policy", GlobalVars.GetStr("RuleOption_EnabledConditionalWindowsLockdownPolicy") }
	};


	/// <summary>
	/// Used by any code from the app to use the functionalities in this VM.
	/// </summary>
	/// <param name="filePath"></param>
	/// <returns></returns>
	internal async Task OpenInConfigurePolicyRuleOptions(string? filePath)
	{
		try
		{
			if (filePath is null) return;

			// Navigate to the Configure Policy Rule Options page
			ViewModelProvider.NavigationService.Navigate(typeof(Pages.ConfigurePolicyRuleOptions), null);

			// Assign the policy file path to the local variable
			SelectedFilePath = filePath;

			// Load the policy options from the XML and update the UI
			await LoadPolicyOptionsFromXML();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}
}
