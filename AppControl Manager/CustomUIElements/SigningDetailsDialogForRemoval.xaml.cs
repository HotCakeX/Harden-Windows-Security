using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.CustomUIElements;

// https://learn.microsoft.com/en-us/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.controls.contentdialog

internal sealed partial class SigningDetailsDialogForRemoval : ContentDialog
{
	// Properties to access the input value
	internal string? CertificatePath { get; private set; }
	internal string? CertificateCommonName { get; private set; }
	internal string? SignToolPath { get; private set; }
	internal string? XMLPolicyPath { get; private set; }

	// To track whether verification is running so it won't happen again
	// Enabling/Disabling Verification button causes the Primary button to not have its theme properly for some reason
	private bool VerificationRunning;

	// To store the selectable Certificate common names
	private HashSet<string> CertCommonNames = [];

	// To save the policy IDs of the currently deployed base policies coming from the calling method
	private readonly List<string?> basePolicyIDs;

	private readonly string policyIDBeingRemoved;

	internal SigningDetailsDialogForRemoval(List<string?> currentlyDeployedBasePolicyIDs, string idBeingRemoved)
	{
		this.InitializeComponent();

		XamlRoot = App.MainWindow?.Content.XamlRoot;

		// Populate the AutoSuggestBox with possible certificate common names available on the system
		FetchLatestCertificateCNs();

		basePolicyIDs = currentlyDeployedBasePolicyIDs;

		policyIDBeingRemoved = idBeingRemoved;

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
			List<string> suggestions = [.. CertCommonNames.Where(name => name.Contains(query, StringComparison.OrdinalIgnoreCase))];

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

		MainWindow.Instance.NavView_Navigate(typeof(Pages.Settings), null);
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
		SignToolPath = SignToolPathTextBox.Text;
		XMLPolicyPath = XMLPolicyFileTextBox.Text;
	}


	/// <summary>
	/// Event handler for the toggle switch to automatically download SignTool.exe from the Microsoft servers
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void AutoAcquireSignTool_Toggled(object sender, RoutedEventArgs e)
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
		XMLPolicyFileBrowseButton.IsEnabled = false;
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
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void VerifyButton_Click(object sender, RoutedEventArgs e)
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

			#region Verify the certificate

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

			#endregion


			#region Verify Certificate Common Name

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

			#endregion


			#region Verify the XML policy path


			if (string.IsNullOrWhiteSpace(XMLPolicyFileTextBox.Text))
			{
				ShowTeachingTip("Please select the XML policy file of the policy being removed.");
				return;
			}

			if (!File.Exists(XMLPolicyFileTextBox.Text))
			{
				ShowTeachingTip("The selected XML policy file path does not exist");
				return;
			}

			if (!string.Equals(Path.GetExtension(XMLPolicyFileTextBox.Text), ".xml", StringComparison.OrdinalIgnoreCase))
			{
				ShowTeachingTip("You need to select a XML file path with (.xml) extension.");
				return;
			}


			string? possibleDeployedPolicy = null;
			string policyPathFromUI = XMLPolicyFileTextBox.Text;
			SiPolicy.SiPolicy? policyObject = null;

			await Task.Run(() =>
			{
				// Instantiate the selected XML policy file
				policyObject = SiPolicy.Management.Initialize(policyPathFromUI);

				// See if the deployed base policy IDs contain the ID of the policy being removed
				// Only checking among base policies because supplemental policies can be removed normally whether they're signed or not
				possibleDeployedPolicy = basePolicyIDs.FirstOrDefault(
				   x => string.Equals($"{{{x}}}", policyObject.PolicyID, StringComparison.OrdinalIgnoreCase));
			});

			if (possibleDeployedPolicy is null)
			{
				ShowTeachingTip("The selected XML policy file is not deployed on the system.");
				return;
			}

			if (!string.Equals(policyObject!.PolicyID, $"{{{policyIDBeingRemoved}}}", StringComparison.OrdinalIgnoreCase))
			{
				ShowTeachingTip("The selected XML policy file is not the one being removed.");
				return;
			}

			if (policyObject.PolicyType is SiPolicy.PolicyType.SupplementalPolicy)
			{
				ShowTeachingTip("Supplemental policies can be removed normally without requiring re-signing.");
				return;
			}

			#endregion


			#region Verify the SignTool


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


			#endregion


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
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void SignToolBrowseButton_Click(object sender, RoutedEventArgs e)
	{
		string filter = "Executable file|*.exe";

		string? selectedFiles = FileDialogHelper.ShowFilePickerDialog(filter);

		if (!string.IsNullOrWhiteSpace(selectedFiles))
		{
			SignToolPath = selectedFiles;
			SignToolPathTextBox.Text = selectedFiles;
		}
	}


	/// <summary>
	/// Event handler for browse for certificate .cer file button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void CertFileBrowseButton_Click(object sender, RoutedEventArgs e)
	{
		string filter = "Certificate file|*.cer";

		string? selectedFiles = FileDialogHelper.ShowFilePickerDialog(filter);

		if (!string.IsNullOrWhiteSpace(selectedFiles))
		{
			CertificatePath = selectedFiles;
			CertFilePathTextBox.Text = selectedFiles;
		}
	}


	/// <summary>
	/// Event handler for the XML policy file browse button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void XMLPolicyFileBrowseButton_Click(object sender, RoutedEventArgs e)
	{
		string? selectedFiles = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrWhiteSpace(selectedFiles))
		{
			XMLPolicyPath = selectedFiles;
			XMLPolicyFileTextBox.Text = selectedFiles;
		}
	}



}
