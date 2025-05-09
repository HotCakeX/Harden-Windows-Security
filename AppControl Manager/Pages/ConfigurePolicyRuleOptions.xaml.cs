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
using AppControlManager.ViewModels;
using AppControlManager.WindowComponents;
using CommunityToolkit.WinUI.Controls;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

/// <summary>
/// Configures policy rules and manages UI interactions for policy templates. Initializes components, handles file
/// selection, and updates settings dynamically.
/// </summary>
internal sealed partial class ConfigurePolicyRuleOptions : Page, IAnimatedIconsManager
{
	private ConfigurePolicyRuleOptionsVM ViewModel { get; } = App.AppHost.Services.GetRequiredService<ConfigurePolicyRuleOptionsVM>();
	private AppSettings.Main AppSettings { get; } = App.AppHost.Services.GetRequiredService<AppSettings.Main>();
	private SidebarVM sideBarVM { get; } = App.AppHost.Services.GetRequiredService<SidebarVM>();

	/// <summary>
	/// Initializes the ConfigurePolicyRuleOptions class, sets up navigation caching, binds the data context, and generates
	/// settings cards.
	/// </summary>
	internal ConfigurePolicyRuleOptions()
	{
		this.InitializeComponent();

		this.NavigationCacheMode = NavigationCacheMode.Required;

		this.DataContext = ViewModel;

		// Call the method to generate SettingsCards dynamically
		GenerateSettingsCards();
	}

	#region Augmentation Interface

	public void SetVisibility(Visibility visibility)
	{
		// Light up the local page's button icons
		ViewModel.BrowseForXMLPolicyButtonLightAnimatedIconVisibility = visibility;

		sideBarVM.AssignActionPacks(
		(param => LightUp1(), GlobalVars.Rizz.GetString("ConfigurePolicyRuleOptions_ButtonContent")),
		null, null, null, null);
	}

	/// <summary>
	/// Local event handlers that are assigned to the sidebar button
	/// </summary>
	private async void LightUp1()
	{
		PickPolicyFileButton_FlyOut.ShowAt(PickPolicyFileButton);
		ViewModel.SelectedFilePath = MainWindowVM.SidebarBasePolicyPathTextBoxTextStatic;

		await LoadPolicyOptionsFromXML(ViewModel.SelectedFilePath);

		// Expand the settings expander when user selects a policy
		PolicyRuleExpander.IsExpanded = true;
	}

	#endregion

	/// <summary>
	/// Method to dynamically create SettingsCards based on the dictionary keys
	/// </summary>
	private void GenerateSettingsCards()
	{
		foreach (KeyValuePair<string, string> key in ViewModel.RuleOptions)
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
	private async void PickPolicyFileButton_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrWhiteSpace(selectedFile))
		{
			ViewModel.SelectedFilePath = selectedFile;

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
	private async void ApplyTheChangesButton_Click()
	{

		try
		{
			ManageButtonStates(false);
			MainTeachingTip.IsOpen = false;

			if (string.IsNullOrWhiteSpace(ViewModel.SelectedFilePath))
			{
				MainTeachingTip.IsOpen = true;
				MainTeachingTip.Subtitle = GlobalVars.Rizz.GetString("SelectPolicyFileBeforeAddingOptions");
				return;
			}

			// Gather selected rules to add
			OptionType[] selectedOptions = [.. GetSelectedPolicyRuleOptions()];

			await Task.Run(() =>
			{
				CiRuleOptions.Set(ViewModel.SelectedFilePath, rulesToAdd: selectedOptions, RemoveAll: true);
			});

			if (DeployAfterApplyingToggleButton.IsChecked == true)
			{
				await Task.Run(() =>
				{
					DirectoryInfo stagingArea = StagingArea.NewStagingArea("ConfigurePolicyRuleOptionsDeployment");

					string cipPath = Path.Combine(stagingArea.FullName, $"{Path.GetFileName(ViewModel.SelectedFilePath)}.cip");

					SiPolicy.SiPolicy policyObj = Management.Initialize(ViewModel.SelectedFilePath, null);

					if (!policyObj.Rules.Any(x => x.Item is OptionType.EnabledUnsignedSystemIntegrityPolicy))
					{
						_ = DispatcherQueue.TryEnqueue(() =>
						{
							MainTeachingTip.IsOpen = true;
							MainTeachingTip.Subtitle = "The selected policy requires signing. Please use the 'Deploy App Control Policy' page to deploy it as a signed policy.";
						});

						return;
					}

					Management.ConvertXMLToBinary(ViewModel.SelectedFilePath, null, cipPath);

					// If a base policy is being deployed, ensure it's supplemental policy for AppControl Manager also gets deployed
					if (SupplementalForSelf.IsEligible(policyObj, ViewModel.SelectedFilePath))
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
	private async void SetPolicyTemplate_Click()
	{
		try
		{
			ManageButtonStates(false);
			MainTeachingTip.IsOpen = false;

			if (string.IsNullOrWhiteSpace(ViewModel.SelectedFilePath))
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
				CiRuleOptions.Set(ViewModel.SelectedFilePath, template: template);
			});

			// Refresh the UI check boxes
			await LoadPolicyOptionsFromXML(ViewModel.SelectedFilePath);
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
	private void PickPolicyFileButton_FlyOut_Clear_Click()
	{
		ViewModel.SelectedFilePath = null;
		ClearAllCheckBoxes();
	}

	/// <summary>
	/// Event handlers to retrieve latest policy rule option details from the XML file and check/uncheck UI boxes
	/// </summary>
	private async void RefreshRuleOptionsState_Click()
	{
		try
		{
			ManageButtonStates(false);
			MainTeachingTip.IsOpen = false;

			if (ViewModel.SelectedFilePath is not null)
			{
				await LoadPolicyOptionsFromXML(ViewModel.SelectedFilePath);
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
