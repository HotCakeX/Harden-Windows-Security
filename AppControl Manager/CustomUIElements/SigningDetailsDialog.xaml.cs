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
using AppControlManager.IntelGathering;
using AppControlManager.Main;
using AppControlManager.Others;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;

namespace AppControlManager.CustomUIElements;

// https://learn.microsoft.com/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.controls.contentdialog

internal sealed partial class SigningDetailsDialog : ContentDialogV2
{

	private AppSettings.Main AppSettings { get; } = App.AppHost.Services.GetRequiredService<AppSettings.Main>();

	// Properties to access the input value
	internal string? CertificatePath { get; private set; }
	internal string? CertificateCommonName { get; private set; }
	internal string? SignToolPath { get; private set; }

	// To track whether verification is running so it won't happen again
	// Enabling/Disabling Verification button causes the Primary button to not have its theme properly for some reason
	private bool VerificationRunning;

	// To store the selectable Certificate common names
	private IEnumerable<string> CertCommonNames = [];

	// When this argument is provided, the verify button will check the input fields with the policy's details
	private readonly SiPolicy.SiPolicy? policyObjectToVerify;

	internal SigningDetailsDialog(SiPolicy.SiPolicy? policyObject = null)
	{
		this.InitializeComponent();

		policyObjectToVerify = policyObject;

		// Populate the AutoSuggestBox with possible certificate common names available on the system
		FetchLatestCertificateCNs();

		// Get the user configurations
		UserConfiguration currentUserConfigs = UserConfiguration.Get();

		// Fill in the text boxes based on the current user configs
		CertFilePathTextBox.Text = currentUserConfigs.CertificatePath;
		CertificateCommonNameAutoSuggestBox.Text = currentUserConfigs.CertificateCommonName;
		SignToolPathTextBox.Text = currentUserConfigs.SignToolCustomPath;

		// Assign the data from user configurations to the local variables
		CertificatePath = currentUserConfigs.CertificatePath;
		CertificateCommonName = currentUserConfigs.CertificateCommonName;
		SignToolPath = currentUserConfigs.SignToolCustomPath;


		// Set the focus on the Verify button when the Content Dialog opens
		// And highlight it
		VerifyButton.Loaded += async (sender, e) =>
		{
			_ = await FocusManager.TryFocusAsync(VerifyButton, FocusState.Keyboard);
		};

	}


	/// <summary>
	/// Event handler for AutoSuggestBox
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	private void CertificateCNAutoSuggestBox_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
	{
		if (args.Reason == AutoSuggestionBoxTextChangeReason.UserInput)
		{
			string query = sender.Text.ToLowerInvariant();

			// Filter menu items based on the search query
			List<string> suggestions = new(CertCommonNames.Where(name => name.Contains(query, StringComparison.OrdinalIgnoreCase)));

			// Set the filtered items as suggestions in the AutoSuggestBox
			sender.ItemsSource = suggestions;
		}
	}


	/// <summary>
	/// Start suggesting when tap or mouse click happens
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void CertificateCommonNameAutoSuggestBox_GotFocus(object sender, RoutedEventArgs e)
	{
		// Set the filtered items as suggestions in the AutoSuggestBox
		((AutoSuggestBox)sender).ItemsSource = CertCommonNames;
	}


	/// <summary>
	/// Get all of the common names of the certificates in the user/my certificate store over time
	/// </summary>
	private async void FetchLatestCertificateCNs()
	{
		await Task.Run(() =>
		{
			CertCommonNames = CertCNFetcher.GetCertCNs();
		});
	}


	/// <summary>
	/// Event handler for the button that navigates to the Settings page
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void OpenAppSettingsButton_Click(object sender, RoutedEventArgs e)
	{
		// Hide the dialog box
		this.Hide();

		App._nav.Navigate(typeof(Pages.Settings), null);
	}


	/// <summary>
	/// Event handler for the primary button click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	private void OnPrimaryButtonClick(ContentDialogV2 sender, ContentDialogButtonClickEventArgs args)
	{
		// Fill in the text boxes based on the current user configs
		CertificatePath = CertFilePathTextBox.Text;
		CertificateCommonName = CertificateCommonNameAutoSuggestBox.Text;
		SignToolPath = SignToolPathTextBox.Text;
	}


	/// <summary>
	/// Event handler for the toggle switch to automatically download SignTool.exe from the Microsoft servers
	/// </summary>
	private void AutoAcquireSignTool_Toggled()
	{
		if (AutoAcquireSignTool.IsOn)
		{
			SignToolBrowseButton.IsEnabled = false;
			SignToolPathTextBox.IsEnabled = false;
		}
		else
		{
			SignToolBrowseButton.IsEnabled = true;
			SignToolPathTextBox.IsEnabled = true;
		}
	}


	/// <summary>
	/// Disables the input UI elements
	/// </summary>
	private void DisableUIElements()
	{
		SignToolPathTextBox.IsEnabled = false;
		CertificateCommonNameAutoSuggestBox.IsEnabled = false;
		AutoAcquireSignTool.IsEnabled = false;
		CertFileBrowseButton.IsEnabled = false;
		SignToolBrowseButton.IsEnabled = false;
		CertFilePathTextBox.IsEnabled = false;
	}


	/// <summary>
	/// Enables the input UI elements
	/// </summary>
	private void EnableUIElements()
	{
		SignToolPathTextBox.IsEnabled = true;
		CertificateCommonNameAutoSuggestBox.IsEnabled = true;
		AutoAcquireSignTool.IsEnabled = true;
		CertFileBrowseButton.IsEnabled = true;
		SignToolBrowseButton.IsEnabled = true;
		CertFilePathTextBox.IsEnabled = true;
	}


	/// <summary>
	/// To show the Teaching Tip for the Verify button
	/// </summary>
	/// <param name="message"></param>
	private void ShowTeachingTip(string message)
	{
		VerifyButtonTeachingTip.IsOpen = true;

		VerifyButtonTeachingTip.Subtitle = message;
	}


	/// <summary>
	/// Event handler for the Verify button
	/// </summary>
	private async void VerifyButton_Click()
	{

		if (VerificationRunning)
		{
			return;
		}

		bool everythingChecksOut = false;

		VerificationRunning = true;

		try
		{
			// Disable UI elements during verification
			DisableUIElements();

			VerifyButtonContentTextBlock.Text = "Verify";

			VerifyButtonProgressRing.Visibility = Visibility.Visible;

			// Disable the submit button until all checks are done (in case it was enabled)
			this.IsPrimaryButtonEnabled = false;

			VerifyButtonTeachingTip.IsOpen = false;

			// Verify the certificate
			if (string.IsNullOrWhiteSpace(CertFilePathTextBox.Text))
			{
				ShowTeachingTip("Please select a certificate file.");
				return;
			}

			if (!File.Exists(CertFilePathTextBox.Text))
			{
				ShowTeachingTip("The selected certificate file path does not exist");
				return;
			}

			if (!string.Equals(Path.GetExtension(CertFilePathTextBox.Text), ".cer", StringComparison.OrdinalIgnoreCase))
			{
				ShowTeachingTip("You need to select a certificate file path with (.cer) extension.");
				return;
			}


			// Verify Certificate Common Name
			if (string.IsNullOrWhiteSpace(CertificateCommonNameAutoSuggestBox.Text))
			{
				ShowTeachingTip("Please select a certificate common name from the suggestions.");
				return;
			}

			if (!CertCommonNames.Contains(CertificateCommonNameAutoSuggestBox.Text))
			{
				ShowTeachingTip("No certificate was found in the Current User personal store with the selected Common Name.");
				return;
			}


			#region Verify the certificate's detail is available in the XML policy as UpdatePolicySigner

			string certCN = CertificateCommonNameAutoSuggestBox.Text;
			string certPath = CertFilePathTextBox.Text;

			if (policyObjectToVerify is not null)
			{
				bool isValid = false;

				await Task.Run(() =>
				{
					isValid = CertificatePresence.InferCertificatePresence(policyObjectToVerify, certPath, certCN);
				});


				if (!isValid)
				{
					ShowTeachingTip("The selected certificate is not present in the XML policy file as an UpdatePolicySigner or the selected common name does not match the selected certificate's common name, thus it cannot be used to re-sign the policy. Please select the correct certificate.");
					return;
				}

			}

			// If cert object is not passed, only ensure cert CN and cert file match
			else
			{
				if (!CertificatePresence.VerifyCertAndCNMatch(certPath, certCN))
				{
					ShowTeachingTip("The selected certificate file and common name don't match.");
					return;
				}
			}

			#endregion


			// Verify the SignTool
			if (!AutoAcquireSignTool.IsOn)
			{

				if (string.IsNullOrWhiteSpace(SignToolPathTextBox.Text))
				{
					ShowTeachingTip("Please select the path to SignTool.exe or enable the auto-acquire option.");
					return;
				}

				if (!File.Exists(SignToolPathTextBox.Text))
				{
					ShowTeachingTip("SignTool.exe does not exist in the selected path. You can enable the auto-acquire option if you don't have it.");
					return;
				}

				if (!string.Equals(Path.GetExtension(SignToolPathTextBox.Text), ".exe", StringComparison.OrdinalIgnoreCase))
				{
					ShowTeachingTip("The SignTool path must end with (.exe). You can enable the auto-acquire option if you don't have it.");
					return;
				}
			}
			else
			{
				try
				{
					VerifyButtonContentTextBlock.Text = "Downloading SignTool";

					string newSignToolPath;

					// Get the SignTool.exe path
					newSignToolPath = await Task.Run(() => SignToolHelper.GetSignToolPath());

					// Assign it to the local variable
					SignToolPath = newSignToolPath;

					// Set it to the UI text box
					SignToolPathTextBox.Text = newSignToolPath;
				}

				finally
				{
					VerifyButtonContentTextBlock.Text = "Verify";
				}
			}


			// If everything checks out then enable the Primary button for submission
			this.IsPrimaryButtonEnabled = true;

			everythingChecksOut = true;

			// Set the SignTool.exe path that was verified to be valid to the user configurations
			_ = UserConfiguration.Set(SignToolCustomPath: SignToolPath);

			// Set certificate details that were verified to the user configurations
			_ = UserConfiguration.Set(CertificateCommonName: CertificateCommonNameAutoSuggestBox.Text, CertificatePath: CertFilePathTextBox.Text);
		}
		finally
		{
			VerifyButtonProgressRing.Visibility = Visibility.Collapsed;

			// If verification failed then re-enable the UI elements
			if (!everythingChecksOut)
			{
				EnableUIElements();
			}
			else
			{
				VerifyButtonContentTextBlock.Text = "Verification Successful";
			}

			VerificationRunning = false;
		}
	}


	/// <summary>
	/// Event handler for SignTool.exe browse button
	/// </summary>
	private void SignToolBrowseButton_Click()
	{
		string? selectedFiles = FileDialogHelper.ShowFilePickerDialog(GlobalVars.ExecutablesPickerFilter);

		if (!string.IsNullOrWhiteSpace(selectedFiles))
		{
			SignToolPath = selectedFiles;
			SignToolPathTextBox.Text = selectedFiles;
		}
	}


	/// <summary>
	/// Event handler for browse for certificate .cer file button
	/// </summary>
	private void CertFileBrowseButton_Click()
	{
		string? selectedFiles = FileDialogHelper.ShowFilePickerDialog(GlobalVars.CertificatePickerFilter);

		if (!string.IsNullOrWhiteSpace(selectedFiles))
		{
			CertificatePath = selectedFiles;
			CertFilePathTextBox.Text = selectedFiles;
		}
	}
}
