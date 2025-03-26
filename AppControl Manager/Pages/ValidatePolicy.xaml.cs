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
using System.Threading.Tasks;
using AppControlManager.Main;
using AppControlManager.Others;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

/// <summary>
/// Validates an XML policy file selected by the user and displays the result in an info bar. It handles errors and
/// updates UI elements accordingly.
/// </summary>
internal sealed partial class ValidatePolicy : Page
{
	/// <summary>
	/// Initializes a new instance of the ValidatePolicy class. Sets the navigation cache mode to required.
	/// </summary>
	internal ValidatePolicy()
	{
		this.InitializeComponent();

		this.NavigationCacheMode = NavigationCacheMode.Required;
	}

	/// <summary>
	/// Validates an App Control XML policy file by allowing the user to select a file and checking its validity.
	/// </summary>
	private async void ValidateXML()
	{

		try
		{
			MainInfoBar.Message = "Browse for an App Control XML policy file";
			MainInfoBar.Severity = InfoBarSeverity.Informational;
			MainInfoBar.IsOpen = true;
			MainInfoBar.IsClosable = false;
			MainInfoBar.Title = "Status";

			BrowseForXMLSettingsCard.IsEnabled = false;
			BrowseForXMLButton.IsEnabled = false;

			string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

			bool isValid = false;

			if (!string.IsNullOrEmpty(selectedFile))
			{
				await Task.Run(() =>
				{
					isValid = CiPolicyTest.TestCiPolicy(selectedFile);
				});
			}
			else
			{
				MainInfoBar.IsOpen = false;
				return;
			}

			if (isValid)
			{
				MainInfoBar.Message = $"The selected policy file '{selectedFile}' is valid.";
				MainInfoBar.Severity = InfoBarSeverity.Success;
				MainInfoBar.Title = "Valid";
			}
			else
			{
				MainInfoBar.Message = $"The selected policy file '{selectedFile}' is not valid.";
				MainInfoBar.Severity = InfoBarSeverity.Warning;
				MainInfoBar.Title = "Invalid";
			}

		}
		catch (Exception ex)
		{
			MainInfoBar.Message = ex.Message;
			MainInfoBar.Severity = InfoBarSeverity.Error;
			MainInfoBar.Title = "Invalid";
		}
		finally
		{
			MainInfoBar.IsClosable = true;
			BrowseForXMLSettingsCard.IsEnabled = true;
			BrowseForXMLButton.IsEnabled = true;
		}
	}

}
