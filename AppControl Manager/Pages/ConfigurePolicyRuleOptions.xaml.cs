using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AppControlManager.Others;
using CommunityToolkit.WinUI.Controls;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;
using static AppControlManager.Main.CiRuleOptions;

namespace AppControlManager.Pages;

public sealed partial class ConfigurePolicyRuleOptions : Page, Sidebar.IAnimatedIconsManager
{
	// Property to hold the keys of the PolicyRuleOptionsActual dictionary
	private List<string> PolicyRuleOptionsKeys { get; set; }

	// To store the selected policy path
	private string? SelectedFilePath;

	public ConfigurePolicyRuleOptions()
	{
		this.InitializeComponent();

		this.NavigationCacheMode = NavigationCacheMode.Enabled;

		// Initialize the keys property with dictionary keys
		PolicyRuleOptionsKeys = [.. PolicyRuleOptionsActual.Keys];

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
			button1.Content = "Configure Policy Rule Options";

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
	private void LightUp1(object sender, RoutedEventArgs e)
	{
		PickPolicyFileButton_FlyOut.ShowAt(PickPolicyFileButton);
		PickPolicyFileButton_TextBox.Text = unsignedBasePolicyPathFromSidebar;
		SelectedFilePath = unsignedBasePolicyPathFromSidebar;
	}

	#endregion


	/// <summary>
	/// Method to dynamically create SettingsCards based on the dictionary keys
	/// </summary>
	private void GenerateSettingsCards()
	{
		foreach (string key in PolicyRuleOptionsKeys)
		{
			// Create a new SettingsCard
			SettingsCard settingsCard = new()
			{
				ContentAlignment = ContentAlignment.Left,
				IsClickEnabled = true,
				IsActionIconVisible = false
			};

			// Create a new CheckBox
			CheckBox checkBox = new()
			{
				Content = key
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
	private async Task LoadPolicyOptionsFromXML(string filePath)
	{

		CodeIntegrityPolicy codeIntegrityPolicy = null!;

		await Task.Run(() =>
		{
			codeIntegrityPolicy = new(filePath, null);
		});

		// Iterate through UI checkboxes and update their state
		foreach (var item in PolicyRuleExpander.Items)
		{
			if (item is SettingsCard settingsCard && settingsCard.Content is CheckBox checkBox)
			{
				string key = checkBox.Content?.ToString()!;

				if (codeIntegrityPolicy.Rules is not null && codeIntegrityPolicy.Rules.Contains(key))
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
				MainTeachingTip.Subtitle = "Please select a policy file before adding options.";
				return;
			}

			// Gather selected rules to add
			PolicyRuleOptions[] selectedOptions = GetSelectedPolicyRuleOptions();

			await Task.Run(() =>
			{
				Set(SelectedFilePath, rulesToAdd: selectedOptions, RemoveAll: true);
			});

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
				MainTeachingTip.Subtitle = "Please select a policy file before setting a template.";
				return;
			}

			// Retrieve the selected item from the ComboBox
			if (PolicyTemplatesComboBox.SelectedItem is not ComboBoxItem selectedComboBoxItem)
			{

				MainTeachingTip.IsOpen = true;
				MainTeachingTip.Subtitle = "Please select a policy template from the dropdown.";
				return;
			}

			// Convert the ComboBoxItem content to the corresponding PolicyTemplate enum value
			if (!Enum.TryParse(selectedComboBoxItem.Content.ToString(), out PolicyTemplate template))
			{
				MainTeachingTip.IsOpen = true;
				MainTeachingTip.Subtitle = "Invalid policy template selected. Please choose a valid option.";
				return;
			}


			// Call the Set method with only the filePath and template parameters
			await Task.Run(() =>
			{
				Set(SelectedFilePath, template: template);
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
	private PolicyRuleOptions[] GetSelectedPolicyRuleOptions()
	{
		List<PolicyRuleOptions> selectedRules = [];

		// Iterate through each SettingsCard in the PolicyRuleExpander
		foreach (var item in PolicyRuleExpander.Items)
		{
			if (item is SettingsCard settingsCard && settingsCard.Content is CheckBox checkBox && checkBox.IsChecked == true)
			{
				// Get the content of the checkbox, which is the dictionary key
				string? key = checkBox.Content?.ToString();

				if (!string.IsNullOrEmpty(key) && PolicyRuleOptionsActual.TryGetValue(key, out int value))
				{
					// Convert to PolicyRuleOptions enum and add to the list
					selectedRules.Add((PolicyRuleOptions)value);
				}
			}
		}

		return [.. selectedRules];
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
				MainTeachingTip.Subtitle = "Please select a policy file before retrieving its rule options status.";
				return;
			}
		}
		finally
		{
			ManageButtonStates(true);
		}
	}
}
