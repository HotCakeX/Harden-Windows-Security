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
using AppControlManager.IntelGathering;
using AppControlManager.Main;
using AppControlManager.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;

namespace AppControlManager.CustomUIElements;

// https://learn.microsoft.com/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.controls.contentdialog

internal sealed partial class SigningDetailsDialogForRemoval : ContentDialogV2
{

	private AppSettings.Main AppSettings => App.Settings;

	// Properties to access the input value
	internal string? CertificatePath { get; private set; }
	internal string? CertificateCommonName { get; private set; }
	internal string? XMLPolicyPath { get; private set; }

	// To track whether verification is running so it won't happen again
	// Enabling/Disabling Verification button causes the Primary button to not have its theme properly for some reason
	private bool VerificationRunning;

	// To store the selectable Certificate common names
	private IEnumerable<string> CertCommonNames = [];

	// To save the policy IDs of the currently deployed base policies coming from the calling method
	private readonly List<string?> basePolicyIDs;

	private readonly string policyIDBeingRemoved;

	internal SigningDetailsDialogForRemoval(List<string?> currentlyDeployedBasePolicyIDs, string idBeingRemoved)
	{
		InitializeComponent();

		// Populate the AutoSuggestBox with possible certificate common names available on the system
		FetchLatestCertificateCNs();

		basePolicyIDs = currentlyDeployedBasePolicyIDs;

		policyIDBeingRemoved = idBeingRemoved;

		// Get the user configurations
		UserConfiguration currentUserConfigs = UserConfiguration.Get();

		// Fill in the text boxes based on the current user configs
		CertFilePathTextBox.Text = currentUserConfigs.CertificatePath;
		CertificateCommonNameAutoSuggestBox.Text = currentUserConfigs.CertificateCommonName;

		// Assign the data from user configurations to the local variables
		CertificatePath = currentUserConfigs.CertificatePath;
		CertificateCommonName = currentUserConfigs.CertificateCommonName;
	}

	/// <summary>
	/// Event handler for when the Verify button is loaded.
	/// Sets the focus on the Verify button when the Content Dialog opens.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void VerifyButton_Loaded(object sender, RoutedEventArgs e)
	{
		try
		{
			// Ensure we're on the UI thread
			if (this.DispatcherQueue is not null)
			{
				// Use DispatcherQueue to ensure we're on the UI thread
				_ = this.DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Normal, async () =>
				{
					try
					{
						// Small delay to ensure the button is fully loaded and ready
						await Task.Delay(50);

						// Attempt to set focus
						FocusMovementResult focusResult = await FocusManager.TryFocusAsync(VerifyButton, FocusState.Keyboard);

						// If focus setting failed, try again with a different focus state
						if (!focusResult.Succeeded)
						{
							await Task.Delay(100);
							_ = FocusManager.TryFocusAsync(VerifyButton, FocusState.Programmatic).GetAwaiter().GetResult();
						}
					}
					catch (Exception ex)
					{
						Logger.Write($"Failed to set focus on VerifyButton: {ex.Message}");
					}
				});
			}
			else
			{
				// Fallback: try setting focus directly without async
				try
				{
					_ = FocusManager.TryFocusAsync(VerifyButton, FocusState.Keyboard);
				}
				catch (Exception ex)
				{
					Logger.Write($"Failed to set focus on VerifyButton (fallback): {ex.Message}");
				}
			}
		}
		catch (Exception ex)
		{
			Logger.Write($"Exception in VerifyButton_Loaded: {ex.Message}");
		}
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
		try
		{
			await Task.Run(() =>
			{
				CertCommonNames = CertCNFetcher.GetCertCNs();
			});
		}
		catch (Exception ex)
		{
			ShowTeachingTip(ex.Message);
			Logger.Write(ex);
		}
	}

	/// <summary>
	/// Event handler for the button that navigates to the Settings page
	/// </summary>
	private void OpenAppSettingsButton_Click()
	{
		// Hide the dialog box
		this.Hide();

		ViewModelProvider.NavigationService.Navigate(typeof(Pages.Settings), null);
	}

	/// <summary>
	/// Event handler for the primary button click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	private void OnPrimaryButtonClick(ContentDialog sender, ContentDialogButtonClickEventArgs args)
	{
		// Grab the details from the text boxes in the UI and assign them to the local variables
		// So that the method that calls this content dialog can access them
		CertificatePath = CertFilePathTextBox.Text;
		CertificateCommonName = CertificateCommonNameAutoSuggestBox.Text;
		XMLPolicyPath = XMLPolicyFileTextBox.Text;
	}

	/// <summary>
	/// Disables the input UI elements
	/// </summary>
	private void DisableUIElements()
	{
		CertificateCommonNameAutoSuggestBox.IsEnabled = false;
		CertFileBrowseButton.IsEnabled = false;
		CertFilePathTextBox.IsEnabled = false;
		XMLPolicyFileBrowseButton.IsEnabled = false;
	}

	/// <summary>
	/// Enables the input UI elements
	/// </summary>
	private void EnableUIElements()
	{
		CertificateCommonNameAutoSuggestBox.IsEnabled = true;
		CertFileBrowseButton.IsEnabled = true;
		CertFilePathTextBox.IsEnabled = true;
		XMLPolicyFileBrowseButton.IsEnabled = true;
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

			VerifyButtonContentTextBlock.Text = GlobalVars.GetStr("VerifyButtonText");

			VerifyButtonProgressRing.Visibility = Visibility.Visible;

			// Disable the submit button until all checks are done (in case it was enabled)
			this.IsPrimaryButtonEnabled = false;

			VerifyButtonTeachingTip.IsOpen = false;

			#region Verify the certificate

			if (string.IsNullOrWhiteSpace(CertFilePathTextBox.Text))
			{
				ShowTeachingTip(GlobalVars.GetStr("PleaseSelectCertificateFileMessage"));
				return;
			}

			if (!File.Exists(CertFilePathTextBox.Text))
			{
				ShowTeachingTip(GlobalVars.GetStr("CertificateFilePathNotExistMessage"));
				return;
			}

			if (!string.Equals(Path.GetExtension(CertFilePathTextBox.Text), ".cer", StringComparison.OrdinalIgnoreCase))
			{
				ShowTeachingTip(GlobalVars.GetStr("CertificateExtensionInvalidMessage"));
				return;
			}

			#endregion

			#region Verify Certificate Common Name

			if (string.IsNullOrWhiteSpace(CertificateCommonNameAutoSuggestBox.Text))
			{
				ShowTeachingTip(GlobalVars.GetStr("PleaseSelectCertificateCommonNameMessage"));
				return;
			}

			if (!CertCommonNames.Contains(CertificateCommonNameAutoSuggestBox.Text))
			{
				ShowTeachingTip(GlobalVars.GetStr("CertificateCommonNameNotFoundMessage"));
				return;
			}

			#endregion

			#region Verify the XML policy path

			if (string.IsNullOrWhiteSpace(XMLPolicyFileTextBox.Text))
			{
				ShowTeachingTip(GlobalVars.GetStr("PleaseSelectXmlPolicyFileMessage"));
				return;
			}

			if (!File.Exists(XMLPolicyFileTextBox.Text))
			{
				ShowTeachingTip(GlobalVars.GetStr("XmlPolicyFilePathNotExistMessage"));
				return;
			}

			if (!string.Equals(Path.GetExtension(XMLPolicyFileTextBox.Text), ".xml", StringComparison.OrdinalIgnoreCase))
			{
				ShowTeachingTip(GlobalVars.GetStr("XmlPolicyExtensionInvalidMessage"));
				return;
			}

			string? possibleDeployedPolicy = null;
			string policyPathFromUI = XMLPolicyFileTextBox.Text;
			SiPolicy.SiPolicy? policyObject = null;

			await Task.Run(() =>
			{
				// Instantiate the selected XML policy file
				policyObject = SiPolicy.Management.Initialize(policyPathFromUI, null);

				// See if the deployed base policy IDs contain the ID of the policy being removed
				// Only checking among base policies because supplemental policies can be removed normally whether they're signed or not
				possibleDeployedPolicy = basePolicyIDs.FirstOrDefault(
				   x => string.Equals($"{{{x}}}", policyObject.PolicyID, StringComparison.OrdinalIgnoreCase));
			});

			if (possibleDeployedPolicy is null)
			{
				ShowTeachingTip(GlobalVars.GetStr("XmlPolicyNotDeployedMessage"));
				return;
			}

			if (!string.Equals(policyObject!.PolicyID, $"{{{policyIDBeingRemoved}}}", StringComparison.OrdinalIgnoreCase))
			{
				ShowTeachingTip(GlobalVars.GetStr("XmlPolicyNotBeingRemovedMessage"));
				return;
			}

			if (policyObject.PolicyType is SiPolicy.PolicyType.SupplementalPolicy)
			{
				ShowTeachingTip(GlobalVars.GetStr("SupplementalPoliciesRemovalMessage"));
				return;
			}

			#endregion

			#region Verify the certificate's detail is available in the XML policy as UpdatePolicySigner

			string certFilePath = CertFilePathTextBox.Text;
			string certCN = CertificateCommonNameAutoSuggestBox.Text;

			bool certIsUpdatePolicySigner = false;

			await Task.Run(() =>
			{
				certIsUpdatePolicySigner = CertificatePresence.InferCertificatePresence(policyObject, certFilePath, certCN);
			});

			if (!certIsUpdatePolicySigner)
			{
				ShowTeachingTip(GlobalVars.GetStr("CertificateNotInPolicyRemovalMessage"));
				return;
			}

			#endregion

			// If everything checks out then enable the Primary button for submission
			this.IsPrimaryButtonEnabled = true;

			everythingChecksOut = true;

			// Set certificate details that were verified to the user configurations
			_ = UserConfiguration.Set(CertificateCommonName: CertificateCommonNameAutoSuggestBox.Text, CertificatePath: CertFilePathTextBox.Text);

			// Set the focus on the Primary button after verification has been successful
			Button? primaryButton = this.GetTemplateChild("PrimaryButton") as Button;
			if (primaryButton is not null)
			{
				try
				{
					// Ensure we're on the UI thread
					if (this.DispatcherQueue is not null)
					{
						// Use DispatcherQueue to ensure we're on the UI thread
						_ = this.DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Normal, async () =>
						{
							try
							{
								// Small delay to ensure the button is fully loaded and ready
								await Task.Delay(50);

								// Attempt to set focus on the primary button
								FocusMovementResult focusResult = await FocusManager.TryFocusAsync(primaryButton, FocusState.Keyboard);

								// If focus setting failed, try again with a different focus state
								if (!focusResult.Succeeded)
								{
									await Task.Delay(100);
									_ = FocusManager.TryFocusAsync(primaryButton, FocusState.Programmatic).GetAwaiter().GetResult();
								}
							}
							catch (Exception ex)
							{
								Logger.Write($"Failed to set focus on PrimaryButton: {ex.Message}");
							}
						});
					}
					else
					{
						// Fallback: try setting focus directly without async
						try
						{
							_ = FocusManager.TryFocusAsync(primaryButton, FocusState.Keyboard);
						}
						catch (Exception ex)
						{
							Logger.Write($"Failed to set focus on PrimaryButton (fallback): {ex.Message}");
						}
					}
				}
				catch (Exception ex)
				{
					Logger.Write($"Exception in setting focus on PrimaryButton: {ex.Message}");
				}
			}
		}
		catch (Exception ex)
		{
			ShowTeachingTip(ex.Message);
			Logger.Write(ex);
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
				VerifyButtonContentTextBlock.Text = GlobalVars.GetStr("VerificationSuccessfulText");
			}

			VerificationRunning = false;
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

	/// <summary>
	/// Event handler for the XML policy file browse button
	/// </summary>
	private void XMLPolicyFileBrowseButton_Click()
	{
		string? selectedFiles = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrWhiteSpace(selectedFiles))
		{
			XMLPolicyPath = selectedFiles;
			XMLPolicyFileTextBox.Text = selectedFiles;
		}
	}
}
