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

using System.Globalization;
using AppControlManager.Main;
using AppControlManager.Others;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

/// <summary>
/// Initializes the page component and sets the navigation cache mode to required. Handles the Fetch button click event
/// to retrieve and display secure policy settings.
/// </summary>
internal sealed partial class GetSecurePolicySettings : Page
{
	/// <summary>
	/// Initializes the component and sets the navigation cache mode to required, ensuring the page maintains its state
	/// during navigation.
	/// </summary>
	internal GetSecurePolicySettings()
	{
		this.InitializeComponent();

		// Make sure navigating to/from this page maintains its state
		this.NavigationCacheMode = NavigationCacheMode.Required;
	}

	/// <summary>
	/// Event handler for the Fetch button
	/// </summary>
	private void InvokeButton_Click()
	{
		// Retrieve input values
		string provider = ProviderTextBox.Text;
		string key = KeyTextBox.Text;
		string valueName = ValueNameTextBox.Text;

		// Check if all fields are filled
		if (string.IsNullOrWhiteSpace(provider) || string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(valueName))
		{
			InfoBar.Message = GlobalVars.Rizz.GetString("GetSecurePolicySettings_FillAllFields");
			InfoBar.Severity = InfoBarSeverity.Warning;
			InfoBar.Title = GlobalVars.Rizz.GetString("GetSecurePolicySettings_InputRequired");
			InfoBar.IsOpen = true;
			return;
		}

		// Call the Invoke method
		SecurePolicySetting result = GetCIPolicySetting.Invoke(provider, key, valueName);

		if (result.StatusCode is not 0)
		{
			InfoBar.Message = GlobalVars.Rizz.GetString("GetSecurePolicySettings_NoPolicyMessage");
			InfoBar.Severity = InfoBarSeverity.Informational;
			InfoBar.Title = GlobalVars.Rizz.GetString("GetSecurePolicySettings_PolicyNotFound");
			InfoBar.IsOpen = true;
		}
		else
		{
			InfoBar.Message = GlobalVars.Rizz.GetString("GetSecurePolicySettings_PolicyFoundMessage");
			InfoBar.Severity = InfoBarSeverity.Success;
			InfoBar.Title = GlobalVars.Rizz.GetString("GetSecurePolicySettings_PolicyFound");
			InfoBar.IsOpen = true;
		}

		// Populate result fields
		ValueTextBox.Text = result.Value?.ToString();
		ValueTypeTextBox.Text = result.ValueType.ToString();
		ValueSizeTextBox.Text = result.ValueSize.ToString(CultureInfo.InvariantCulture);
		StatusTextBox.Text = result.Status.ToString();
		StatusCodeTextBox.Text = result.StatusCode.ToString(CultureInfo.InvariantCulture);
	}
}
