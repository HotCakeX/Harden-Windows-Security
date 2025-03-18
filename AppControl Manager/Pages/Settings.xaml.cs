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
using AppControlManager.AppSettings;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using static AppControlManager.AppSettings.AppSettingsCls;

namespace AppControlManager.Pages;

/// <summary>
/// The Settings class manages user configurations and UI elements for a settings page. It initializes settings, handles
/// events, and updates the UI.
/// </summary>
public sealed partial class Settings : Page
{

#pragma warning disable CA1822
	internal SettingsVM ViewModel { get; } = App.AppHost.Services.GetRequiredService<SettingsVM>();
#pragma warning restore CA1822

	/// <summary>
	/// Initializes the settings page, loading user configurations into UI elements and setting up event handlers for user
	/// interactions.
	/// </summary>
	public Settings()
	{
		this.InitializeComponent();

		this.DataContext = ViewModel;

		// Make sure navigating to/from this page maintains its state
		this.NavigationCacheMode = NavigationCacheMode.Required;

		#region Load the user configurations in the UI elements

		NavigationViewBackgroundToggle.IsOn = GetSetting<bool>(SettingKeys.NavViewBackground);

		SoundToggleSwitch.IsOn = GetSetting<bool>(SettingKeys.SoundSetting);

		ListViewsCenterVerticallyUponSelectionToggleSwitch.IsOn = GetSetting<bool>(SettingKeys.ListViewsVerticalCentering);

		CacheSecurityCatalogsScanResultsToggleSwitch.IsOn = GetSetting<bool>(SettingKeys.CacheSecurityCatalogsScanResults);

		BackgroundComboBox.SelectedIndex = (GetSetting<string>(SettingKeys.BackDropBackground)) switch
		{
			"MicaAlt" => 0,
			"Mica" => 1,
			"Acrylic" => 2,
			_ => 0
		};


		ThemeComboBox.SelectedIndex = (GetSetting<string>(SettingKeys.AppTheme)) switch
		{
			"Use System Setting" => 0,
			"Dark" => 1,
			"Light" => 2,
			_ => 0
		};


		IconsStyleComboBox.SelectedIndex = (GetSetting<string>(SettingKeys.IconsStyle)) switch
		{
			"Animated" => 0,
			"Windows Accent" => 1,
			"Monochromatic" => 2,
			_ => 2
		};

		#endregion


		// Instead of defining the events in the XAML, defining them here after performing changes on the UI elements based on the saved settings
		// This way we don't trigger the event handlers just by changing UI element values
		// Since queries for saved settings already happen in the Main Window, App and other respective places
		// This also Prevents a dark flash when using brighter theme because of triggering events twice unnecessarily.
		NavigationViewBackgroundToggle.Toggled += NavigationViewBackground_Toggled;
		BackgroundComboBox.SelectionChanged += BackgroundComboBox_SelectionChanged;
		ThemeComboBox.SelectionChanged += ThemeComboBox_SelectionChanged;
		NavigationMenuLocation.SelectionChanged += NavigationViewLocationComboBox_SelectionChanged;
		SoundToggleSwitch.Toggled += SoundToggleSwitch_Toggled;
		IconsStyleComboBox.SelectionChanged += IconsStyleComboBox_SelectionChanged;
		ListViewsCenterVerticallyUponSelectionToggleSwitch.Toggled += ListViewsCenterVerticallyUponSelectionToggleSwitch_Toggled;
		CacheSecurityCatalogsScanResultsToggleSwitch.Toggled += CacheSecurityCatalogsScanResultsToggleSwitch_Toggled;
	}


	/// <summary>
	/// Event handler for the IconsStyle ComboBox selection change event.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void IconsStyleComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		// Get the ComboBox that triggered the event
		ComboBox comboBox = (ComboBox)sender;

		// Get the selected item from the ComboBox
		string selectedIconsStyle = (string)comboBox.SelectedItem;

		// Raise the global BackgroundChanged event
		IconsStyleManager.OnIconsStylesChanged(selectedIconsStyle);

		SaveSetting(SettingKeys.IconsStyle, selectedIconsStyle);
	}


	/// <summary>
	/// Event handler for the Background ComboBox selection change event.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void BackgroundComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		// Get the ComboBox that triggered the event
		ComboBox comboBox = (ComboBox)sender;

		// Get the selected item from the ComboBox (x:String)
		string selectedBackdrop = (string)comboBox.SelectedItem;

		// Raise the global BackgroundChanged event
		ThemeManager.OnBackgroundChanged(selectedBackdrop);

		SaveSetting(SettingKeys.BackDropBackground, selectedBackdrop);
	}

	/// <summary>
	/// Event handler for the NavigationViewLocation ComboBox selection change event.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void NavigationViewLocationComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		ComboBox comboBox = (ComboBox)sender;

		// This won't work with Native AOT mode
		// string? selectedLocation = (comboBox?.SelectedItem as ComboBoxItem)?.Content?.ToString();

		// This however works and uses WinRT method
		// string? selectedLocation = (comboBox?.SelectedItem.As<ComboBoxItem>())?.Content?.ToString();

		// This method works too but it needs <x:String> and not <ComboBoxItem>
		string selectedLocation = (string)comboBox.SelectedItem;

		// Raise the global OnNavigationViewLocationChanged event
		NavigationViewLocationManager.OnNavigationViewLocationChanged(selectedLocation);
	}

	/// <summary>
	/// Event handler for the Theme ComboBox selection change event.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void ThemeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		// Get the ComboBox that triggered the event
		ComboBox comboBox = (ComboBox)sender;

		// Get the selected item from the ComboBox
		string selectedTheme = (string)comboBox.SelectedItem;

		// Raise the global BackgroundChanged event
		AppThemeManager.OnAppThemeChanged(selectedTheme);

		SaveSetting(SettingKeys.AppTheme, selectedTheme);
	}


	/// <summary>
	/// Event handler for the NavigationViewBackground toggle switch change event.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void NavigationViewBackground_Toggled(object sender, RoutedEventArgs e)
	{
		// Get the ToggleSwitch that triggered the event
		ToggleSwitch toggleSwitch = (ToggleSwitch)sender;

		// Get the state of the ToggleSwitch
		bool isBackgroundOn = toggleSwitch.IsOn;

		// Notify NavigationBackgroundManager when the toggle switch is changed
		NavigationBackgroundManager.OnNavigationBackgroundChanged(isBackgroundOn);

		SaveSetting(SettingKeys.NavViewBackground, isBackgroundOn);
	}


	/// <summary>
	/// Event handler for the Sound toggle switch change event.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void SoundToggleSwitch_Toggled(object sender, RoutedEventArgs e)
	{
		// Get the ToggleSwitch that triggered the event
		ToggleSwitch toggleSwitch = (ToggleSwitch)sender;

		// Get the state of the toggle switch (on or off)
		bool isSoundOn = toggleSwitch.IsOn;

		// Raise the event to notify the app of the sound setting change
		SoundManager.OnSoundSettingChanged(isSoundOn);

		// Save the setting to the local app settings
		SaveSetting(SettingKeys.SoundSetting, isSoundOn);
	}


	// When the button to get the user configurations on the settings card is pressed
	private void GetConfigurationButton_Click(object sender, RoutedEventArgs e)
	{
		UserConfiguration userConfig = UserConfiguration.Get();

		SignedPolicyPathTextBox.Text = userConfig.SignedPolicyPath ?? string.Empty;
		UnsignedPolicyPathTextBox.Text = userConfig.UnsignedPolicyPath ?? string.Empty;
		SignToolCustomPathTextBox.Text = userConfig.SignToolCustomPath ?? string.Empty;
		CertificateCommonNameAutoSuggestBox.Text = userConfig.CertificateCommonName ?? string.Empty;
		CertificatePathTextBox.Text = userConfig.CertificatePath ?? string.Empty;

		// Expand the settings expander to make the configurations visible
		MainUserConfigurationsSettingsExpander.IsExpanded = true;
	}

	// When the edit button of any field is pressed
	private void EditButton_Click(object sender, RoutedEventArgs e)
	{
		string fieldName = ((Button)sender).Tag.ToString()!;
		string? newValue = null;

		// Determine the new value based on the associated TextBox
		switch (fieldName)
		{
			case "SignedPolicyPath":
				newValue = SignedPolicyPathTextBox.Text;
				break;
			case "UnsignedPolicyPath":
				newValue = UnsignedPolicyPathTextBox.Text;
				break;
			case "SignToolCustomPath":
				newValue = SignToolCustomPathTextBox.Text;
				break;
			case "CertificateCommonName":
				newValue = CertificateCommonNameAutoSuggestBox.Text;
				break;
			case "CertificatePath":
				newValue = CertificatePathTextBox.Text;
				break;
			default:
				break;
		}

		_ = UserConfiguration.Set(
			SignedPolicyPath: string.Equals(fieldName, "SignedPolicyPath", StringComparison.OrdinalIgnoreCase) ? newValue : null,
			UnsignedPolicyPath: string.Equals(fieldName, "UnsignedPolicyPath", StringComparison.OrdinalIgnoreCase) ? newValue : null,
			SignToolCustomPath: string.Equals(fieldName, "SignToolCustomPath", StringComparison.OrdinalIgnoreCase) ? newValue : null,
			CertificateCommonName: string.Equals(fieldName, "CertificateCommonName", StringComparison.OrdinalIgnoreCase) ? newValue : null,
			CertificatePath: string.Equals(fieldName, "CertificatePath", StringComparison.OrdinalIgnoreCase) ? newValue : null
		);

		Logger.Write($"Edited {fieldName} to {newValue}");
	}

	// When the clear button of any field is pressed
	private void ClearButton_Click(object sender, RoutedEventArgs e)
	{
		string fieldName = ((Button)sender).Tag.ToString()!;

		UserConfiguration.Remove(
			SignedPolicyPath: string.Equals(fieldName, "SignedPolicyPath", StringComparison.OrdinalIgnoreCase),
			UnsignedPolicyPath: string.Equals(fieldName, "UnsignedPolicyPath", StringComparison.OrdinalIgnoreCase),
			SignToolCustomPath: string.Equals(fieldName, "SignToolCustomPath", StringComparison.OrdinalIgnoreCase),
			CertificateCommonName: string.Equals(fieldName, "CertificateCommonName", StringComparison.OrdinalIgnoreCase),
			CertificatePath: string.Equals(fieldName, "CertificatePath", StringComparison.OrdinalIgnoreCase)
		);

		switch (fieldName)
		{
			case "SignedPolicyPath":
				SignedPolicyPathTextBox.Text = string.Empty;
				break;
			case "UnsignedPolicyPath":
				UnsignedPolicyPathTextBox.Text = string.Empty;
				break;
			case "SignToolCustomPath":
				SignToolCustomPathTextBox.Text = string.Empty;
				break;
			case "CertificateCommonName":
				CertificateCommonNameAutoSuggestBox.Text = string.Empty;
				break;
			case "CertificatePath":
				CertificatePathTextBox.Text = string.Empty;
				break;
			default:
				break;
		}

		Logger.Write($"Cleared {fieldName}");
	}

	// When the browse button of any field is pressed
	private void BrowseButton_Click(object sender, RoutedEventArgs e)
	{
		string fieldName = ((Button)sender).Tag.ToString()!;

		switch (fieldName)
		{
			case "SignedPolicyPath":
				SignedPolicyPathTextBox.Text = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);
				break;
			case "UnsignedPolicyPath":
				UnsignedPolicyPathTextBox.Text = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);
				break;
			case "SignToolCustomPath":
				SignToolCustomPathTextBox.Text = FileDialogHelper.ShowFilePickerDialog(GlobalVars.ExecutablesPickerFilter);
				break;
			case "CertificatePath":
				CertificatePathTextBox.Text = FileDialogHelper.ShowFilePickerDialog(GlobalVars.CertificatePickerFilter);
				break;
			default:
				break;
		}
	}



	private void ListViewsCenterVerticallyUponSelectionToggleSwitch_Toggled(object sender, RoutedEventArgs e)
	{
		// Get the ToggleSwitch that triggered the event
		ToggleSwitch toggleSwitch = (ToggleSwitch)sender;

		// Get the state of the toggle switch (on or off)
		bool IsOn = toggleSwitch.IsOn;

		// Save the setting to the local app settings
		SaveSetting(SettingKeys.ListViewsVerticalCentering, IsOn);
	}


	private void CacheSecurityCatalogsScanResultsToggleSwitch_Toggled(object sender, RoutedEventArgs e)
	{
		// Get the ToggleSwitch that triggered the event
		ToggleSwitch toggleSwitch = (ToggleSwitch)sender;

		// Get the state of the toggle switch (on or off)
		bool IsOn = toggleSwitch.IsOn;

		// Save the setting to the local app settings
		SaveSetting(SettingKeys.CacheSecurityCatalogsScanResults, IsOn);
	}


	#region Settings cards clicks event handlers

	private void BackgroundComboBoxSettingsCard_Click(object sender, RoutedEventArgs e)
	{
		BackgroundComboBox.IsDropDownOpen = true;
	}

	private void ThemeComboBoxSettingsCard_Click(object sender, RoutedEventArgs e)
	{
		ThemeComboBox.IsDropDownOpen = true;
	}

	private void IconsStyleComboBoxSettingsCard_Click(object sender, RoutedEventArgs e)
	{
		IconsStyleComboBox.IsDropDownOpen = true;
	}

	private void NavigationMenuLocationSettingsCard_Click(object sender, RoutedEventArgs e)
	{
		NavigationMenuLocation.IsDropDownOpen = true;
	}

	private void SoundToggleSwitchSettingsCard_Click(object sender, RoutedEventArgs e)
	{

		SoundToggleSwitch.IsOn = !SoundToggleSwitch.IsOn;
		SoundToggleSwitch_Toggled(SoundToggleSwitch, new RoutedEventArgs());
	}

	private void NavigationViewBackgroundToggleSettingsCard_Click(object sender, RoutedEventArgs e)
	{
		NavigationViewBackgroundToggle.IsOn = !NavigationViewBackgroundToggle.IsOn;
		NavigationViewBackground_Toggled(NavigationViewBackgroundToggle, new RoutedEventArgs());
	}

	private void ListViewsCenterVerticallyUponSelectionSettingsCard_Click(object sender, RoutedEventArgs e)
	{
		ListViewsCenterVerticallyUponSelectionToggleSwitch.IsOn = !ListViewsCenterVerticallyUponSelectionToggleSwitch.IsOn;
		ListViewsCenterVerticallyUponSelectionToggleSwitch_Toggled(ListViewsCenterVerticallyUponSelectionToggleSwitch, new RoutedEventArgs());
	}

	private void CacheSecurityCatalogsScanResultsSettingsCard_Click(object sender, RoutedEventArgs e)
	{
		CacheSecurityCatalogsScanResultsToggleSwitch.IsOn = !CacheSecurityCatalogsScanResultsToggleSwitch.IsOn;
		CacheSecurityCatalogsScanResultsToggleSwitch_Toggled(CacheSecurityCatalogsScanResultsToggleSwitch, new RoutedEventArgs());
	}

	#endregion

}
