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
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.SiPolicy;
using CommunityToolkit.WinUI.Controls;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

public sealed partial class ConfigurePolicyRuleOptions : Page, Sidebar.IAnimatedIconsManager
{
	// To store the selected policy path
	private string? SelectedFilePath;

	public ConfigurePolicyRuleOptions()
	{
		this.InitializeComponent();

		this.NavigationCacheMode = NavigationCacheMode.Required;

		// Call the method to generate SettingsCards dynamically
		GenerateSettingsCards();

		// Register the click event for the new Set button in the PolicyTemplate section
		SetPolicyTemplate.Click += SetPolicyTemplate_Click;
	}


	#region Augmentation Interface

	private string? unsignedBasePolicyPathFromSidebar;

	// Implement the SetVisibility method required by IAnimatedIconsManager
	public void SetVisibility(Visibility visibility, string? unsignedBasePolicyPath, Button button1, Button button2, Button button3, Button button4, Button button5)
	{
		// Light up the local page's button icons
		PickPolicyFileButtonAnimatedIconLight.Visibility = visibility;

		// Light up the sidebar buttons' icons
		button1.Visibility = visibility;

		// Set the incoming text which is from sidebar for unsigned policy path to a local private variable
		unsignedBasePolicyPathFromSidebar = unsignedBasePolicyPath;


		if (visibility is Visibility.Visible)
		{
			// Assign sidebar buttons' content texts
			button1.Content = GlobalVars.Rizz.GetString("ConfigurePolicyRuleOptions_ButtonContent");

			// Assign a local event handler to the sidebar button
			button1.Click += LightUp1;
			// Save a reference to the event handler we just set for tracking
			Sidebar.EventHandlersTracking.SidebarUnsignedBasePolicyConnect1EventHandler = LightUp1;
		}

	}

	/// <summary>
	/// Local event handlers that are assigned to the sidebar button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void LightUp1(object sender, RoutedEventArgs e)
	{
		PickPolicyFileButton_FlyOut.ShowAt(PickPolicyFileButton);
		PickPolicyFileButton_TextBox.Text = unsignedBasePolicyPathFromSidebar;
		SelectedFilePath = unsignedBasePolicyPathFromSidebar;

		await LoadPolicyOptionsFromXML(SelectedFilePath);

		// Expand the settings expander when user selects a policy
		PolicyRuleExpander.IsExpanded = true;
	}

	#endregion


	private static readonly Dictionary<string, string> RuleOptions = new()
	{
		{ "Enabled:UMCI", GlobalVars.Rizz.GetString("RuleOption_EnabledUMCI") },
		{ "Enabled:Boot Menu Protection", GlobalVars.Rizz.GetString("RuleOption_EnabledBootMenuProtection") },
		{ "Required:WHQL", GlobalVars.Rizz.GetString("RuleOption_RequiredWHQL") },
		{ "Enabled:Audit Mode", GlobalVars.Rizz.GetString("RuleOption_EnabledAuditMode") },
		{ "Disabled:Flight Signing", GlobalVars.Rizz.GetString("RuleOption_DisabledFlightSigning") },
		{ "Enabled:Inherit Default Policy", GlobalVars.Rizz.GetString("RuleOption_EnabledInheritDefaultPolicy") },
		{ "Enabled:Unsigned System Integrity Policy", GlobalVars.Rizz.GetString("RuleOption_EnabledUnsignedSystemIntegrityPolicy") },
		{ "Required:EV Signers", GlobalVars.Rizz.GetString("RuleOption_RequiredEVSigners") },
		{ "Enabled:Advanced Boot Options Menu", GlobalVars.Rizz.GetString("RuleOption_EnabledAdvancedBootOptionsMenu") },
		{ "Enabled:Boot Audit On Failure", GlobalVars.Rizz.GetString("RuleOption_EnabledBootAuditOnFailure") },
		{ "Disabled:Script Enforcement", GlobalVars.Rizz.GetString("RuleOption_DisabledScriptEnforcement") },
		{ "Required:Enforce Store Applications", GlobalVars.Rizz.GetString("RuleOption_RequiredEnforceStoreApplications") },
		{ "Enabled:Managed Installer", GlobalVars.Rizz.GetString("RuleOption_EnabledManagedInstaller") },
		{ "Enabled:Intelligent Security Graph Authorization", GlobalVars.Rizz.GetString("RuleOption_EnabledIntelligentSecurityGraphAuthorization") },
		{ "Enabled:Invalidate EAs on Reboot", GlobalVars.Rizz.GetString("RuleOption_EnabledInvalidateEAsOnReboot") },
		{ "Enabled:Update Policy No Reboot", GlobalVars.Rizz.GetString("RuleOption_EnabledUpdatePolicyNoReboot") },
		{ "Enabled:Allow Supplemental Policies", GlobalVars.Rizz.GetString("RuleOption_EnabledAllowSupplementalPolicies") },
		{ "Disabled:Runtime FilePath Rule Protection", GlobalVars.Rizz.GetString("RuleOption_DisabledRuntimeFilePathRuleProtection") },
		{ "Enabled:Dynamic Code Security",GlobalVars.Rizz.GetString("RuleOption_EnabledDynamicCodeSecurity") },
		{ "Enabled:Revoked Expired As Unsigned", GlobalVars.Rizz.GetString("RuleOption_EnabledRevokedExpiredAsUnsigned") },
		{ "Enabled:Developer Mode Dynamic Code Trust", GlobalVars.Rizz.GetString("RuleOption_EnabledDeveloperModeDynamicCodeTrust") },
		{ "Enabled:Secure Setting Policy", GlobalVars.Rizz.GetString("RuleOption_EnabledSecureSettingPolicy") },
		{ "Enabled:Conditional Windows Lockdown Policy", GlobalVars.Rizz.GetString("RuleOption_EnabledConditionalWindowsLockdownPolicy") }
	};


	/// <summary>
	/// Method to dynamically create SettingsCards based on the dictionary keys
	/// </summary>
	private void GenerateSettingsCards()
	{
		foreach (KeyValuePair<string, string> key in RuleOptions)
		{
			// Create a new SettingsCard
			SettingsCard settingsCard = new()
			{
				IsClickEnabled = true,
				IsActionIconVisible = false,
				Header = key.Key,
				Description = key.Value
			};

			ToolTip toolTip = new()
			{
				Content = key.Value,
				HorizontalAlignment = HorizontalAlignment.Center,
				VerticalAlignment = VerticalAlignment.Center
			};

			// Attach the tooltip to the settings card
			ToolTipService.SetToolTip(settingsCard, toolTip);

			// Create a new CheckBox
			CheckBox checkBox = new()
			{
				Tag = key.Key,
				HorizontalAlignment = HorizontalAlignment.Right
			};

			// Add the CheckBox to the SettingsCard
			settingsCard.Content = checkBox;

			// Attach click event to the SettingsCard so click/tap on settings card will be relayed to the check box
			settingsCard.Click += (sender, e) =>
			{
				checkBox.IsChecked = !checkBox.IsChecked;
			};

			// Add the SettingsCard to the SettingsExpander.Items collection
			PolicyRuleExpander.Items.Add(settingsCard);
		}
	}


	/// <summary>
	/// Event handler for the browse button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void PickPolicyFileButton_Click(object sender, RoutedEventArgs e)
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrWhiteSpace(selectedFile))
		{
			// Display the file in the flyout's text box
			PickPolicyFileButton_TextBox.Text = selectedFile;

			SelectedFilePath = selectedFile;

			// Expand the settings expander when user selects a policy
			PolicyRuleExpander.IsExpanded = true;

			// Load the policy options from the XML and update the UI
			await LoadPolicyOptionsFromXML(selectedFile);
		}
	}

	/// <summary>
	/// When the XML policy file is selected by the user, get its rule options and check/uncheck the check boxes in the UI accordingly
	/// </summary>
	/// <param name="filePath"></param>
	private async Task LoadPolicyOptionsFromXML(string? filePath)
	{

		SiPolicy.SiPolicy policyObj = null!;

		await Task.Run(() =>
		{
			policyObj = Management.Initialize(filePath, null);
		});

		// All the Policy OptionTypes in the selected XML file
		IEnumerable<OptionType> policyRules = policyObj.Rules.Select(x => x.Item);

		// Iterate through UI checkboxes and update their state
		foreach (var item in PolicyRuleExpander.Items)
		{
			if (item is SettingsCard settingsCard && settingsCard.Content is CheckBox checkBox)
			{
				// Get the tag of the checkbox
				string key = checkBox.Tag.ToString()!;

				if (policyRules.Contains(CustomDeserialization.ConvertStringToOptionType(key)))
				{
					checkBox.IsChecked = true;
				}
				else
				{
					checkBox.IsChecked = false;
				}
			}
		}
	}


	/// <summary>
	/// Event handler for when the Apply button is pressed
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void ApplyTheChangesButton_Click(object sender, RoutedEventArgs e)
	{

		try
		{
			ManageButtonStates(false);
			MainTeachingTip.IsOpen = false;

			if (string.IsNullOrWhiteSpace(SelectedFilePath))
			{
				MainTeachingTip.IsOpen = true;
				MainTeachingTip.Subtitle = GlobalVars.Rizz.GetString("SelectPolicyFileBeforeAddingOptions");
				return;
			}

			// Gather selected rules to add
			OptionType[] selectedOptions = [.. GetSelectedPolicyRuleOptions()];

			await Task.Run(() =>
			{
				CiRuleOptions.Set(SelectedFilePath, rulesToAdd: selectedOptions, RemoveAll: true);
			});

			if (DeployAfterApplyingToggleButton.IsChecked == true)
			{
				await Task.Run(() =>
				{
					DirectoryInfo stagingArea = StagingArea.NewStagingArea("ConfigurePolicyRuleOptionsDeployment");

					string cipPath = Path.Combine(stagingArea.FullName, $"{Path.GetFileName(SelectedFilePath)}.cip");

					SiPolicy.SiPolicy policyObj = Management.Initialize(SelectedFilePath, null);

					if (!policyObj.Rules.Any(x => x.Item is OptionType.EnabledUnsignedSystemIntegrityPolicy))
					{
						_ = DispatcherQueue.TryEnqueue(() =>
						{
							MainTeachingTip.IsOpen = true;
							MainTeachingTip.Subtitle = "The selected policy requires signing. Please use the 'Deploy App Control Policy' page to deploy it as a signed policy.";
						});

						return;
					}

					PolicyToCIPConverter.Convert(SelectedFilePath, cipPath);

					// If a base policy is being deployed, ensure it's supplemental policy for AppControl Manager also gets deployed
					if (SupplementalForSelf.IsEligible(policyObj, SelectedFilePath))
						SupplementalForSelf.Deploy(stagingArea.FullName, policyObj.PolicyID);

					CiToolHelper.UpdatePolicy(cipPath);
				});
			}
		}
		finally
		{
			ManageButtonStates(true);
		}
	}


	/// <summary>
	/// Event handler for the Set button click in the PolicyTemplate section
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void SetPolicyTemplate_Click(object sender, RoutedEventArgs e)
	{

		try
		{
			ManageButtonStates(false);
			MainTeachingTip.IsOpen = false;

			if (string.IsNullOrWhiteSpace(SelectedFilePath))
			{
				MainTeachingTip.IsOpen = true;
				MainTeachingTip.Subtitle = GlobalVars.Rizz.GetString("SelectPolicyFileBeforeSettingTemplate");
				return;
			}

			// Retrieve the selected item from the ComboBox
			string selectedItem = (string)PolicyTemplatesComboBox.SelectedItem;

			// Convert the ComboBoxItem content to the corresponding PolicyTemplate enum value
			CiRuleOptions.PolicyTemplate template = Enum.Parse<CiRuleOptions.PolicyTemplate>(selectedItem);

			// Call the Set method with only the filePath and template parameters
			await Task.Run(() =>
			{
				CiRuleOptions.Set(SelectedFilePath, template: template);
			});

			// Refresh the UI check boxes
			await LoadPolicyOptionsFromXML(SelectedFilePath);
		}
		finally
		{
			ManageButtonStates(true);
		}
	}

	/// <summary>
	/// Manages buttons' disablement/enablement
	/// </summary>
	/// <param name="Enable"></param>
	private void ManageButtonStates(bool Enable)
	{
		SetPolicyTemplate.IsEnabled = Enable;
		RefreshRuleOptionsState.IsEnabled = Enable;
		ApplyTheChangesButton.IsEnabled = Enable;
	}


	/// <summary>
	/// Helper method to get selected policy rule options from the UI checkboxes
	/// </summary>
	/// <returns></returns>
	private List<OptionType> GetSelectedPolicyRuleOptions()
	{
		List<OptionType> selectedRules = [];

		// Iterate through each SettingsCard in the PolicyRuleExpander
		foreach (var item in PolicyRuleExpander.Items)
		{
			if (item is SettingsCard settingsCard && settingsCard.Content is CheckBox checkBox && checkBox.IsChecked == true)
			{
				// Get the tag of the checkbox
				string? key = checkBox.Tag?.ToString();

				if (!string.IsNullOrEmpty(key))
				{
					selectedRules.Add(CustomDeserialization.ConvertStringToOptionType(key));
				}
			}
		}
		return selectedRules;
	}


	/// <summary>
	/// Uncheck all of the rule options check boxes in the UI
	/// </summary>
	private void ClearAllCheckBoxes()
	{
		// Iterate through each SettingsCard in the PolicyRuleExpander
		foreach (var item in PolicyRuleExpander.Items)
		{
			if (item is SettingsCard settingsCard && settingsCard.Content is CheckBox checkBox && checkBox.IsChecked == true)
			{
				checkBox.IsChecked = false;
			}
		}
	}


	/// <summary>
	/// Event handler for the flyout's clear button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void PickPolicyFileButton_FlyOut_Clear_Click(object sender, RoutedEventArgs e)
	{
		PickPolicyFileButton_TextBox.Text = null;
		SelectedFilePath = null;
		ClearAllCheckBoxes();
	}

	private void PickPolicyFileButton_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!PickPolicyFileButton_FlyOut.IsOpen)
			PickPolicyFileButton_FlyOut.ShowAt(PickPolicyFileButton);
	}

	private void PickPolicyFileButton_Holding(object sender, HoldingRoutedEventArgs e)
	{
		if (e.HoldingState is HoldingState.Started)
			if (!PickPolicyFileButton_FlyOut.IsOpen)
				PickPolicyFileButton_FlyOut.ShowAt(PickPolicyFileButton);
	}

	/// <summary>
	/// Event handlers to retrieve latest policy rule option details from the XML file and check/uncheck UI boxes
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void RefreshRuleOptionsState_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			ManageButtonStates(false);
			MainTeachingTip.IsOpen = false;

			if (SelectedFilePath is not null)
			{
				await LoadPolicyOptionsFromXML(SelectedFilePath);
			}
			else
			{
				MainTeachingTip.IsOpen = true;
				MainTeachingTip.Subtitle = GlobalVars.Rizz.GetString("SelectPolicyFileBeforeRetrievingOptions");
				return;
			}
		}
		finally
		{
			ManageButtonStates(true);
		}
	}
}
