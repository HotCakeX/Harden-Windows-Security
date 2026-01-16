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

	internal ConfigurePolicyRuleOptionsVM() => MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

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
	/// To store the selected policy.
	/// </summary>
	internal PolicyFileRepresent? SelectedPolicy { get; set => SP(ref field, value); }

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
				await Task.Run(() =>
				{
					// Initialize the policy
					SiPolicy.SiPolicy tempPolicyObj = Management.Initialize(selectedFile, null);

					SelectedPolicy = new(tempPolicyObj) { FilePath = selectedFile };
				});

				// Load the policy options from the XML and update the UI
				LoadPolicyOptionsFromXML();
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// When the policy file is selected by the user, get its rule options and check/uncheck the check boxes in the UI accordingly
	/// </summary>
	internal void LoadPolicyOptionsFromXML()
	{
		try
		{
			if (SelectedPolicy is null)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("SelectPolicyFileBeforeRetrievingOptions"));
				return;
			}

			// All the Policy OptionTypes in the selected XML file
			List<OptionType> policyRules = SelectedPolicy.PolicyObj.Rules.Select(x => x.Item).ToList();

			// Update each checkbox state based on the policy rules
			EnabledUMCICheckBox = policyRules.Contains(OptionType.EnabledUMCI);
			EnabledBootMenuProtectionCheckBox = policyRules.Contains(OptionType.EnabledBootMenuProtection);
			RequiredWHQLCheckBox = policyRules.Contains(OptionType.RequiredWHQL);
			EnabledAuditModeCheckBox = policyRules.Contains(OptionType.EnabledAuditMode);
			DisabledFlightSigningCheckBox = policyRules.Contains(OptionType.DisabledFlightSigning);
			EnabledInheritDefaultPolicyCheckBox = policyRules.Contains(OptionType.EnabledInheritDefaultPolicy);
			EnabledUnsignedSystemIntegrityPolicyCheckBox = policyRules.Contains(OptionType.EnabledUnsignedSystemIntegrityPolicy);
			RequiredEVSignersCheckBox = policyRules.Contains(OptionType.RequiredEVSigners);
			EnabledAdvancedBootOptionsMenuCheckBox = policyRules.Contains(OptionType.EnabledAdvancedBootOptionsMenu);
			EnabledBootAuditOnFailureCheckBox = policyRules.Contains(OptionType.EnabledBootAuditOnFailure);
			DisabledScriptEnforcementCheckBox = policyRules.Contains(OptionType.DisabledScriptEnforcement);
			RequiredEnforceStoreApplicationsCheckBox = policyRules.Contains(OptionType.RequiredEnforceStoreApplications);
			EnabledManagedInstallerCheckBox = policyRules.Contains(OptionType.EnabledManagedInstaller);
			EnabledIntelligentSecurityGraphAuthorizationCheckBox = policyRules.Contains(OptionType.EnabledIntelligentSecurityGraphAuthorization);
			EnabledInvalidateEAsOnRebootCheckBox = policyRules.Contains(OptionType.EnabledInvalidateEAsonReboot);
			EnabledUpdatePolicyNoRebootCheckBox = policyRules.Contains(OptionType.EnabledUpdatePolicyNoReboot);
			EnabledAllowSupplementalPoliciesCheckBox = policyRules.Contains(OptionType.EnabledAllowSupplementalPolicies);
			DisabledRuntimeFilePathRuleProtectionCheckBox = policyRules.Contains(OptionType.DisabledRuntimeFilePathRuleProtection);
			EnabledDynamicCodeSecurityCheckBox = policyRules.Contains(OptionType.EnabledDynamicCodeSecurity);
			EnabledRevokedExpiredAsUnsignedCheckBox = policyRules.Contains(OptionType.EnabledRevokedExpiredAsUnsigned);
			EnabledDeveloperModeDynamicCodeTrustCheckBox = policyRules.Contains(OptionType.EnabledDeveloperModeDynamicCodeTrust);
			EnabledSecureSettingPolicyCheckBox = policyRules.Contains(OptionType.EnabledSecureSettingPolicy);
			EnabledConditionalWindowsLockdownPolicyCheckBox = policyRules.Contains(OptionType.EnabledConditionalWindowsLockdownPolicy);

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
	internal async void ApplyTheChangesButton_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
	{
		try
		{
			ElementsAreEnabled = false;

			if (SelectedPolicy is null)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("SelectPolicyFileBeforeAddingOptions"));
				return;
			}

			// Gather selected rules to add
			List<OptionType> selectedOptions = GetSelectedPolicyRuleOptions();

			await Task.Run(async () =>
			{
				SelectedPolicy.PolicyObj = CiRuleOptions.Set(SelectedPolicy.PolicyObj, rulesToAdd: selectedOptions, RemoveAll: true);

				if (SelectedPolicy.FilePath is not null)
				{
					// Save the changes to the policy XML file.
					Management.SavePolicyToFile(SelectedPolicy.PolicyObj, SelectedPolicy.FilePath);
				}

				// Assign the modified policy to the Sidebar
				ViewModelProvider.MainWindowVM.AssignToSidebar(SelectedPolicy);

				MainWindow.TriggerTransferIconAnimationStatic((UIElement)sender);
			});

			if (DeployAfterApplyingToggleButton)
			{
				await Task.Run(() =>
				{
					if (!SelectedPolicy.PolicyObj.Rules.Any(x => x.Item is OptionType.EnabledUnsignedSystemIntegrityPolicy))
					{
						MainInfoBar.WriteWarning(GlobalVars.GetStr("TeachingTipSubtitlePolicyRequiresSigning"));
						return;
					}

					// If a base policy is being deployed, ensure it's supplemental policy for AppControl Manager also gets deployed
					if (SupplementalForSelf.IsEligible(SelectedPolicy.PolicyObj))
						SupplementalForSelf.Deploy(SelectedPolicy.PolicyObj.PolicyID);

					CiToolHelper.UpdatePolicy(Management.ConvertXMLToBinary(SelectedPolicy.PolicyObj));
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
	internal async void SetPolicyTemplate_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
	{
		try
		{
			ElementsAreEnabled = false;

			if (SelectedPolicy is null)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("SelectPolicyFileBeforeSettingTemplate"));
				return;
			}

			// Convert the ComboBoxItem content to the corresponding PolicyTemplate enum value
			CiRuleOptions.PolicyTemplate template = Enum.Parse<CiRuleOptions.PolicyTemplate>(PolicyTemplatesComboBoxSelectedItem);

			// Call the Set method with only the filePath and template parameters
			await Task.Run(async () =>
			{
				SelectedPolicy.PolicyObj = CiRuleOptions.Set(SelectedPolicy.PolicyObj, template: template);

				if (SelectedPolicy.FilePath is not null)
				{
					// Save the changes to the policy XML file.
					Management.SavePolicyToFile(SelectedPolicy.PolicyObj, SelectedPolicy.FilePath);
				}

				// Assign the modified policy to the Sidebar
				ViewModelProvider.MainWindowVM.AssignToSidebar(SelectedPolicy);

				MainWindow.TriggerTransferIconAnimationStatic((UIElement)sender);
			});

			// Refresh the UI check boxes
			LoadPolicyOptionsFromXML();
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
		SelectedPolicy = null;
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

			if (SelectedPolicy is not null)
			{
				LoadPolicyOptionsFromXML();
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
	/// Helper method to get selected policy rule options from the UI checkboxes.
	/// </summary>
	/// <returns></returns>
	internal List<OptionType> GetSelectedPolicyRuleOptions()
	{
		List<OptionType> selectedRules = [];

		// Check each checkbox individually
		if (EnabledUMCICheckBox)
			selectedRules.Add(OptionType.EnabledUMCI);
		if (EnabledBootMenuProtectionCheckBox)
			selectedRules.Add(OptionType.EnabledBootMenuProtection);
		if (RequiredWHQLCheckBox)
			selectedRules.Add(OptionType.RequiredWHQL);
		if (EnabledAuditModeCheckBox)
			selectedRules.Add(OptionType.EnabledAuditMode);
		if (DisabledFlightSigningCheckBox)
			selectedRules.Add(OptionType.DisabledFlightSigning);
		if (EnabledInheritDefaultPolicyCheckBox)
			selectedRules.Add(OptionType.EnabledInheritDefaultPolicy);
		if (EnabledUnsignedSystemIntegrityPolicyCheckBox)
			selectedRules.Add(OptionType.EnabledUnsignedSystemIntegrityPolicy);
		if (RequiredEVSignersCheckBox)
			selectedRules.Add(OptionType.RequiredEVSigners);
		if (EnabledAdvancedBootOptionsMenuCheckBox)
			selectedRules.Add(OptionType.EnabledAdvancedBootOptionsMenu);
		if (EnabledBootAuditOnFailureCheckBox)
			selectedRules.Add(OptionType.EnabledBootAuditOnFailure);
		if (DisabledScriptEnforcementCheckBox)
			selectedRules.Add(OptionType.DisabledScriptEnforcement);
		if (RequiredEnforceStoreApplicationsCheckBox)
			selectedRules.Add(OptionType.RequiredEnforceStoreApplications);
		if (EnabledManagedInstallerCheckBox)
			selectedRules.Add(OptionType.EnabledManagedInstaller);
		if (EnabledIntelligentSecurityGraphAuthorizationCheckBox)
			selectedRules.Add(OptionType.EnabledIntelligentSecurityGraphAuthorization);
		if (EnabledInvalidateEAsOnRebootCheckBox)
			selectedRules.Add(OptionType.EnabledInvalidateEAsonReboot);
		if (EnabledUpdatePolicyNoRebootCheckBox)
			selectedRules.Add(OptionType.EnabledUpdatePolicyNoReboot);
		if (EnabledAllowSupplementalPoliciesCheckBox)
			selectedRules.Add(OptionType.EnabledAllowSupplementalPolicies);
		if (DisabledRuntimeFilePathRuleProtectionCheckBox)
			selectedRules.Add(OptionType.DisabledRuntimeFilePathRuleProtection);
		if (EnabledDynamicCodeSecurityCheckBox)
			selectedRules.Add(OptionType.EnabledDynamicCodeSecurity);
		if (EnabledRevokedExpiredAsUnsignedCheckBox)
			selectedRules.Add(OptionType.EnabledRevokedExpiredAsUnsigned);
		if (EnabledDeveloperModeDynamicCodeTrustCheckBox)
			selectedRules.Add(OptionType.EnabledDeveloperModeDynamicCodeTrust);
		if (EnabledSecureSettingPolicyCheckBox)
			selectedRules.Add(OptionType.EnabledSecureSettingPolicy);
		if (EnabledConditionalWindowsLockdownPolicyCheckBox)
			selectedRules.Add(OptionType.EnabledConditionalWindowsLockdownPolicy);

		return selectedRules;
	}

	/// <summary>
	/// Uncheck all of the rule options check boxes in the UI.
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

	/// <summary>
	/// Used by the XAML UI.
	/// </summary>
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
	internal async Task OpenInConfigurePolicyRuleOptions(SiPolicy.PolicyFileRepresent? policy)
	{
		try
		{
			if (policy is null) return;

			ElementsAreEnabled = false;

			// Navigate to the Configure Policy Rule Options page
			ViewModelProvider.NavigationService.Navigate(typeof(Pages.ConfigurePolicyRuleOptions), null);

			// Assign the policy file path to the local variable
			SelectedPolicy = policy;

			// Load the policy options from the XML and update the UI
			LoadPolicyOptionsFromXML();
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
}
