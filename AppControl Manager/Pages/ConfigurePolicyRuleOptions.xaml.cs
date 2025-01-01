using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using CommunityToolkit.WinUI.Controls;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using static AppControlManager.CiRuleOptions;

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

		// Register click events for buttons
		ResetSelections.Click += ResetSelections_Click;
		Add.Click += Add_Click;
		Remove.Click += Remove_Click;

		// Register the click event for the new Set button in the PolicyTemplate section
		SetPolicyTemplate.Click += SetPolicyTemplate_Click;

		// Register the click event for the new Select All button
		SelectAll.Click += SelectAll_Click;
	}


	#region Augmentation Interface


	private string? unsignedBasePolicyPathFromSidebar;


	// Implement the SetVisibility method required by IAnimatedIconsManager
	public void SetVisibility(Visibility visibility, string? unsignedBasePolicyPath, Button button1, Button button2)
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
				ContentAlignment = ContentAlignment.Left
			};

			// Create a new CheckBox
			CheckBox checkBox = new()
			{
				// Set the content to the key from the dictionary
				Content = key
			};

			// Add the CheckBox to the SettingsCard
			settingsCard.Content = checkBox;

			// Add the SettingsCard to the SettingsExpander.Items collection
			PolicyRuleExpander.Items.Add(settingsCard);
		}
	}


	/// <summary>
	/// Event handler for the browse button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void PickPolicyFileButton_Click(object sender, RoutedEventArgs e)
	{

		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Display the file in the flyout's text box
			PickPolicyFileButton_TextBox.Text = selectedFile;

			SelectedFilePath = selectedFile;
		}
	}


	/// <summary>
	/// Event handler for the ResetSelections button click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void ResetSelections_Click(object sender, RoutedEventArgs e)
	{
		// Iterate through each SettingsCard in the PolicyRuleExpander
		foreach (var item in PolicyRuleExpander.Items)
		{
			if (item is SettingsCard settingsCard && settingsCard.Content is CheckBox checkBox)
			{
				// Uncheck the CheckBox
				checkBox.IsChecked = false;
			}
		}
	}


	/// <summary>
	/// Event handler for the Add button click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void Add_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			Add.IsEnabled = false;
			Remove.IsEnabled = false;
			SetPolicyTemplate.IsEnabled = false;

			if (string.IsNullOrWhiteSpace(SelectedFilePath))
			{
				ShowMessage("Please select a policy file before adding options.");
				return;
			}

			// Gather selected rules to add
			PolicyRuleOptions[] selectedOptions = GetSelectedPolicyRuleOptions();

			// Call the Set method with selected options to add
			await Task.Run(() =>
			{
				Set(SelectedFilePath, rulesToAdd: selectedOptions);
			});

		}
		finally
		{
			Add.IsEnabled = true;
			Remove.IsEnabled = true;
			SetPolicyTemplate.IsEnabled = true;
		}

	}


	/// <summary>
	/// Event handler for the Remove button click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void Remove_Click(object sender, RoutedEventArgs e)
	{

		try
		{

			Add.IsEnabled = false;
			Remove.IsEnabled = false;
			SetPolicyTemplate.IsEnabled = false;

			if (string.IsNullOrWhiteSpace(SelectedFilePath))
			{
				ShowMessage("Please select a policy file before removing options.");
				return;
			}

			// Gather selected rules to remove
			PolicyRuleOptions[] selectedOptions = GetSelectedPolicyRuleOptions();


			// Call the Set method with selected options to remove
			await Task.Run(() =>
			{
				Set(SelectedFilePath, rulesToRemove: selectedOptions);
			});

		}
		finally
		{
			Add.IsEnabled = true;
			Remove.IsEnabled = true;
			SetPolicyTemplate.IsEnabled = true;
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

			Add.IsEnabled = false;
			Remove.IsEnabled = false;
			SetPolicyTemplate.IsEnabled = false;

			if (string.IsNullOrWhiteSpace(SelectedFilePath))
			{
				ShowMessage("Please select a policy file before setting a template.");
				return;
			}

			// Retrieve the selected item from the ComboBox
			if (PolicyTemplatesComboBox.SelectedItem is not ComboBoxItem selectedComboBoxItem)
			{
				ShowMessage("Please select a policy template from the dropdown.");
				return;
			}

			// Convert the ComboBoxItem content to the corresponding PolicyTemplate enum value
			if (!Enum.TryParse(selectedComboBoxItem.Content.ToString(), out PolicyTemplate template))
			{
				ShowMessage("Invalid policy template selected. Please choose a valid option.");
				return;
			}


			// Call the Set method with only the filePath and template parameters
			await Task.Run(() =>
			{
				Set(SelectedFilePath, template: template);
			});

		}
		finally
		{
			Add.IsEnabled = true;
			Remove.IsEnabled = true;
			SetPolicyTemplate.IsEnabled = true;
		}

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
	/// Event handler for the "Select All" button click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void SelectAll_Click(object sender, RoutedEventArgs e)
	{
		// Iterate through each SettingsCard in the PolicyRuleExpander
		foreach (var item in PolicyRuleExpander.Items)
		{
			if (item is SettingsCard settingsCard && settingsCard.Content is CheckBox checkBox)
			{
				// Set the CheckBox to checked
				checkBox.IsChecked = true;
			}
		}
	}


	/// <summary>
	/// Helper method to show a simple message dialog
	/// </summary>
	/// <param name="message"></param>
	private async void ShowMessage(string message)
	{
		ContentDialog dialog = new()
		{
			Title = "Information",
			Content = message,
			CloseButtonText = "OK",
			XamlRoot = this.Content.XamlRoot
		};
		_ = await dialog.ShowAsync();
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
	}
}
