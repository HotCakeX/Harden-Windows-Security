using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AppControlManager.CustomUIElements;
using AppControlManager.Logging;
using AppControlManager.SiPolicy;
using AppControlManager.SiPolicyIntel;
using AppControlManager.XMLOps;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

public sealed partial class Deployment : Page, Sidebar.IAnimatedIconsManager
{
	// HashSets to store user input selected files
	private readonly HashSet<string> XMLFiles = [];
	private readonly HashSet<string> SignedXMLFiles = [];
	private readonly HashSet<string> CIPFiles = [];

	public Deployment()
	{
		this.InitializeComponent();

		this.NavigationCacheMode = NavigationCacheMode.Enabled;

		if (GlobalVars.CurrentOSVersion < GlobalVars.VersionFor24H2)
		{
			DeploySignedXMLButton.IsEnabled = false;
			DeploySignedXMLButtonContentTextBlock.Text = "Requires Windows 11 24H2 or later";
		};
	}


	#region Augmentation Interface

	private string? unsignedBasePolicyPathFromSidebar;

	// Implement the SetVisibility method required by IAnimatedIconsManager
	public void SetVisibility(Visibility visibility, string? unsignedBasePolicyPath, Button button1, Button button2)
	{
		// Light up the local page's button icons
		UnsignedXMLFilesLightAnimatedIcon.Visibility = visibility;
		SignedXMLFilesLightAnimatedIcon.Visibility = visibility;

		// Light up the sidebar buttons' icons
		button1.Visibility = visibility;
		button2.Visibility = visibility;

		// Set the incoming text which is from sidebar for unsigned policy path to a local private variable
		unsignedBasePolicyPathFromSidebar = unsignedBasePolicyPath;

		if (visibility is Visibility.Visible)
		{
			// Assign sidebar buttons' content texts
			button1.Content = "Deploy Unsigned Policy";
			button2.Content = "Deploy Signed Policy";

			// Assign a local event handler to the sidebar button
			button1.Click += LightUp1;
			button2.Click += LightUp2;

			// Save a reference to the event handler we just set for tracking
			Sidebar.EventHandlersTracking.SidebarUnsignedBasePolicyConnect1EventHandler = LightUp1;
			Sidebar.EventHandlersTracking.SidebarUnsignedBasePolicyConnect1EventHandler = LightUp2;
		}
	}

	/// <summary>
	/// Local event handlers that are assigned to the sidebar button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void LightUp1(object sender, RoutedEventArgs e)
	{

		if (!string.IsNullOrWhiteSpace(unsignedBasePolicyPathFromSidebar))
		{
			if (XMLFiles.Add(unsignedBasePolicyPathFromSidebar))
			{
				// Append the new file to the TextBox, followed by a newline
				BrowseForXMLPolicyFilesButton_SelectedFilesTextBox.Text += unsignedBasePolicyPathFromSidebar + Environment.NewLine;
			}
		}

		BrowseForXMLPolicyFilesButton_Flyout.ShowAt(BrowseForXMLPolicyFilesButton);
	}

	private void LightUp2(object sender, RoutedEventArgs e)
	{

		if (!string.IsNullOrWhiteSpace(unsignedBasePolicyPathFromSidebar))
		{
			if (SignedXMLFiles.Add(unsignedBasePolicyPathFromSidebar))
			{
				// Append the new file to the TextBox, followed by a newline
				BrowseForSignedXMLPolicyFilesButton_SelectedFilesTextBox.Text += unsignedBasePolicyPathFromSidebar + Environment.NewLine;
			}
		}

		BrowseForSignedXMLPolicyFilesButton_Flyout.ShowAt(BrowseForSignedXMLPolicyFilesButton);
	}

	#endregion




	/// <summary>
	/// Deploy unsigned XML files button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void DeployUnsignedXMLButton_Click(object sender, RoutedEventArgs e)
	{
		if (XMLFiles.Count is 0)
		{
			DeployUnsignedXMLButtonTeachingTip.IsOpen = true;
			return;
		}

		DeployUnsignedXMLButtonTeachingTip.IsOpen = false;

		bool errorsOccurred = false;

		try
		{
			// Disable all the deployment buttons during main operation
			DeployUnsignedXMLButton.IsEnabled = false;
			DeployCIPButton.IsEnabled = false;
			DeploySignedXMLButton.IsEnabled = false;

			StatusInfoBar.Visibility = Visibility.Visible;
			StatusInfoBar.IsOpen = true;
			StatusInfoBar.Message = $"Deploying {XMLFiles.Count} unsigned XML files.";
			StatusInfoBar.Severity = InfoBarSeverity.Informational;
			StatusInfoBar.IsClosable = false;

			MainProgressRing.Visibility = Visibility.Visible;

			// Deploy the selected files
			await Task.Run(() =>
			{

				DirectoryInfo stagingArea = StagingArea.NewStagingArea("UnsignedDeployments");

				// Convert and then deploy each XML file
				foreach (string file in XMLFiles)
				{

					// Instantiate the policy
					SiPolicy.SiPolicy policyObject = Management.Initialize(file);

					if (policyObject.Rules is null || !policyObject.Rules.Any(rule => rule.Item is OptionType.EnabledUnsignedSystemIntegrityPolicy))
					{
						throw new InvalidOperationException($"The XML file '{file}' is a signed policy, use the signed policy deployment section instead!");
					}

					string randomString = GUIDGenerator.GenerateUniqueGUID();

					string xmlFileName = Path.GetFileName(file);

					string CIPFilePath = Path.Combine(stagingArea.FullName, $"{xmlFileName}-{randomString}.cip");

					_ = DispatcherQueue.TryEnqueue(() =>
					{
						StatusInfoBar.Message = $"Currently Deploying XML file: '{file}'";
					});

					// Convert the XML file to CIP
					PolicyToCIPConverter.Convert(file, CIPFilePath);

					// Deploy the CIP file
					CiToolHelper.UpdatePolicy(CIPFilePath);

					// Delete the CIP file after deployment
					File.Delete(CIPFilePath);

					// Don't need to deploy it for the recommended block rules since they are only explicit Deny mode policies
					if (!string.Equals(policyObject.FriendlyName, "Microsoft Windows Recommended User Mode BlockList", StringComparison.OrdinalIgnoreCase))
					{
						if (!string.Equals(policyObject.FriendlyName, "Microsoft Windows Driver Policy", StringComparison.OrdinalIgnoreCase))
						{
							// Make sure the policy is a base policy and it doesn't have allow all rule
							if (policyObject.PolicyType is PolicyType.BasePolicy)
							{
								if (!CheckForAllowAll.Check(file))
								{
									// Deploy the AppControlManager supplemental policy
									SupplementalForSelf.Deploy(stagingArea.FullName, policyObject.PolicyID);
								}
							}
						}
					}
				}
			});
		}

		catch
		{
			errorsOccurred = true;

			StatusInfoBar.Severity = InfoBarSeverity.Error;
			StatusInfoBar.Message = "There was an error deploying the selected XML files";

			throw;
		}
		finally
		{
			if (!errorsOccurred)
			{
				StatusInfoBar.Severity = InfoBarSeverity.Success;
				StatusInfoBar.Message = "Successfully deployed all of the selected XML files";

				// Clear the lists at the end if no errors occurred
				XMLFiles.Clear();

				BrowseForXMLPolicyFilesButton_SelectedFilesTextBox.Text = null;
			}

			// Re-enable all the deploy buttons
			DeployUnsignedXMLButton.IsEnabled = true;
			DeployCIPButton.IsEnabled = true;
			DeploySignedXMLButton.IsEnabled = true;

			MainProgressRing.Visibility = Visibility.Collapsed;
			StatusInfoBar.IsClosable = true;
		}
	}





	/// <summary>
	/// Deploy Signed XML files button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void DeploySignedXMLButton_Click(object sender, RoutedEventArgs e)
	{

		if (SignedXMLFiles.Count is 0)
		{
			DeploySignedXMLButtonTeachingTip.IsOpen = true;
			return;
		}

		DeploySignedXMLButtonTeachingTip.IsOpen = false;


		#region Signing Details acquisition

		string CertCN;
		string CertPath;
		string SignToolPath;

		// Instantiate the Content Dialog
		SigningDetailsDialog customDialog = new();

		// Show the dialog and await its result
		ContentDialogResult result = await customDialog.ShowAsync();

		// Ensure primary button was selected
		if (result is ContentDialogResult.Primary)
		{
			SignToolPath = customDialog.SignToolPath!;
			CertPath = customDialog.CertificatePath!;
			CertCN = customDialog.CertificateCommonName!;
		}
		else
		{
			return;
		}

		#endregion


		bool errorsOccurred = false;

		try
		{
			// Disable all the deployment buttons during main operation
			DeployUnsignedXMLButton.IsEnabled = false;
			DeployCIPButton.IsEnabled = false;
			DeploySignedXMLButton.IsEnabled = false;

			StatusInfoBar.Visibility = Visibility.Visible;
			StatusInfoBar.IsOpen = true;
			StatusInfoBar.Message = $"Deploying {SignedXMLFiles.Count} Signed XML files.";
			StatusInfoBar.Severity = InfoBarSeverity.Informational;
			StatusInfoBar.IsClosable = false;

			MainProgressRing.Visibility = Visibility.Visible;

			// Deploy the selected files
			await Task.Run(() =>
			{

				DirectoryInfo stagingArea = StagingArea.NewStagingArea("SignedDeployments");

				// Convert and then deploy each XML file
				foreach (string file in SignedXMLFiles)
				{

					_ = DispatcherQueue.TryEnqueue(() =>
					{
						StatusInfoBar.Message = $"Currently Deploying XML file: '{file}'";
					});


					// Add certificate's details to the policy
					SiPolicy.SiPolicy policyObject = AddSigningDetails.Add(file, CertPath);

					// Remove the unsigned policy rule option from the policy
					CiRuleOptions.Set(filePath: file, rulesToRemove: [CiRuleOptions.PolicyRuleOptions.EnabledUnsignedSystemIntegrityPolicy]);

					// Define the path for the CIP file
					string randomString = GUIDGenerator.GenerateUniqueGUID();
					string xmlFileName = Path.GetFileName(file);
					string CIPFilePath = Path.Combine(stagingArea.FullName, $"{xmlFileName}-{randomString}.cip");

					string CIPp7SignedFilePath = Path.Combine(stagingArea.FullName, $"{xmlFileName}-{randomString}.cip.p7");

					// Convert the XML file to CIP, overwriting the unsigned one
					PolicyToCIPConverter.Convert(file, CIPFilePath);

					// Sign the CIP
					SignToolHelper.Sign(new FileInfo(CIPFilePath), new FileInfo(SignToolPath), CertCN);

					// Rename the .p7 signed file to .cip 
					File.Move(CIPp7SignedFilePath, CIPFilePath, true);

					// Get all of the deployed base and supplemental policies on the system
					List<CiPolicyInfo> policies = CiToolHelper.GetPolicies(false, true, true);

					CiPolicyInfo? possibleAlreadyDeployedUnsignedVersion = policies.
					FirstOrDefault(x => string.Equals(policyObject.PolicyID.Trim('{', '}'), x.PolicyID, StringComparison.OrdinalIgnoreCase));

					if (possibleAlreadyDeployedUnsignedVersion is not null)
					{
						Logger.Write($"A policy with the same PolicyID {possibleAlreadyDeployedUnsignedVersion.PolicyID} is already deployed on the system in Unsigned version. Removing it before deployed the signed version to prevent boot failures.");

						CiToolHelper.RemovePolicy(possibleAlreadyDeployedUnsignedVersion.PolicyID!);
					}

					// Don't need to deploy it for the recommended block rules since they are only explicit Deny mode policies
					if (!string.Equals(policyObject.FriendlyName, "Microsoft Windows Recommended User Mode BlockList", StringComparison.OrdinalIgnoreCase))
					{
						if (!string.Equals(policyObject.FriendlyName, "Microsoft Windows Driver Policy", StringComparison.OrdinalIgnoreCase))
						{
							// Make sure the policy is a base policy and it doesn't have allow all rule
							if (policyObject.PolicyType is PolicyType.BasePolicy)
							{
								if (!CheckForAllowAll.Check(file))
								{
									// Sign and deploy the required AppControlManager supplemental policy
									SupplementalForSelf.DeploySigned(policyObject.PolicyID, CertPath, SignToolPath, CertCN);
								}
							}
						}
					}

					// Deploy the signed CIP file
					CiToolHelper.UpdatePolicy(CIPFilePath);
				}
			});
		}

		catch
		{
			errorsOccurred = true;

			StatusInfoBar.Severity = InfoBarSeverity.Error;
			StatusInfoBar.Message = "There was an error deploying the selected XML files";

			throw;
		}
		finally
		{
			if (!errorsOccurred)
			{
				StatusInfoBar.Severity = InfoBarSeverity.Success;
				StatusInfoBar.Message = "Successfully deployed all of the selected XML files as Signed policies";

				// Clear the lists at the end if no errors occurred
				SignedXMLFiles.Clear();

				BrowseForSignedXMLPolicyFilesButton_SelectedFilesTextBox.Text = null;
			}

			// Re-enable all the deploy buttons
			DeployUnsignedXMLButton.IsEnabled = true;
			DeployCIPButton.IsEnabled = true;
			DeploySignedXMLButton.IsEnabled = true;

			MainProgressRing.Visibility = Visibility.Collapsed;
			StatusInfoBar.IsClosable = true;
		}
	}






	/// <summary>
	/// Deploy CIP files button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void DeployCIPButton_Click(object sender, RoutedEventArgs e)
	{
		if (CIPFiles.Count is 0)
		{
			DeployCIPButtonTeachingTip.IsOpen = true;
			return;
		}

		DeployCIPButtonTeachingTip.IsOpen = false;

		bool errorsOccurred = false;

		try
		{
			DeployUnsignedXMLButton.IsEnabled = false;
			DeployCIPButton.IsEnabled = false;
			DeploySignedXMLButton.IsEnabled = false;

			StatusInfoBar.Visibility = Visibility.Visible;
			StatusInfoBar.IsOpen = true;
			StatusInfoBar.Message = $"Deploying {CIPFiles.Count} CIP binary files.";
			StatusInfoBar.Severity = InfoBarSeverity.Informational;
			StatusInfoBar.IsClosable = false;

			MainProgressRing.Visibility = Visibility.Visible;

			// Deploy the selected CIP files
			await Task.Run(() =>
			{
				foreach (string file in CIPFiles)
				{
					_ = DispatcherQueue.TryEnqueue(() =>
					{
						StatusInfoBar.Message = $"Currently Deploying CIP file: '{file}'";
					});

					CiToolHelper.UpdatePolicy(file);
				}
			});
		}

		catch
		{
			errorsOccurred = true;

			StatusInfoBar.Severity = InfoBarSeverity.Error;
			StatusInfoBar.Message = "There was an error deploying the selected CIP files";

			throw;
		}
		finally
		{
			if (!errorsOccurred)
			{
				StatusInfoBar.Severity = InfoBarSeverity.Success;
				StatusInfoBar.Message = "Successfully deployed all of the selected CIP files";

				// Clear the list at the end if no errors occurred
				CIPFiles.Clear();

				BrowseForCIPBinaryFilesButton_SelectedFilesTextBox.Text = null;
			}

			DeployUnsignedXMLButton.IsEnabled = true;
			DeployCIPButton.IsEnabled = true;
			DeploySignedXMLButton.IsEnabled = true;

			MainProgressRing.Visibility = Visibility.Collapsed;
			StatusInfoBar.IsClosable = true;
		}
	}





	/// <summary>
	/// Event handler for browse button - Unsigned XML files
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void BrowseForXMLPolicyFilesButton_Click(object sender, RoutedEventArgs e)
	{

		List<string>? selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (selectedFiles is { Count: > 0 })
		{
			foreach (string file in selectedFiles)
			{
				if (XMLFiles.Add(file))
				{
					// Append the new file to the TextBox, followed by a newline
					BrowseForXMLPolicyFilesButton_SelectedFilesTextBox.Text += file + Environment.NewLine;
				}
			}
		}
	}


	/// <summary>
	/// Event handler for Browser button - CIP files
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void BrowseForCIPBinaryFilesButton_Click(object sender, RoutedEventArgs e)
	{
		string filter = "CIP file|*.cip";

		List<string>? selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(filter);

		if (selectedFiles is { Count: > 0 })
		{
			foreach (string file in selectedFiles)
			{
				if (CIPFiles.Add(file))
				{
					// Append the new file to the TextBox, followed by a newline
					BrowseForCIPBinaryFilesButton_SelectedFilesTextBox.Text += file + Environment.NewLine;
				}
			}
		}
	}


	/// <summary>
	/// Clear button for the CIP files deployment button flyout
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void BrowseForCIPBinaryFilesButton_Flyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		BrowseForCIPBinaryFilesButton_SelectedFilesTextBox.Text = null;
		CIPFiles.Clear();
	}


	/// <summary>
	/// Clear button for the unsigned files deployment button flyout
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void BrowseForXMLPolicyFilesButton_Flyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		BrowseForXMLPolicyFilesButton_SelectedFilesTextBox.Text = null;
		XMLFiles.Clear();
	}


	/// <summary>
	/// Clear button for the Signed files deployment button flyout
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void BrowseForSignedXMLPolicyFilesButton_Flyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		BrowseForSignedXMLPolicyFilesButton_SelectedFilesTextBox.Text = null;
		SignedXMLFiles.Clear();
	}


	/// <summary>
	/// Event handler for browse button - Signed XML files
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void BrowseForSignedXMLPolicyFilesButton_Click(object sender, RoutedEventArgs e)
	{

		List<string>? selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (selectedFiles is { Count: > 0 })
		{
			foreach (string file in selectedFiles)
			{
				if (SignedXMLFiles.Add(file))
				{
					// Append the new file to the TextBox, followed by a newline
					BrowseForSignedXMLPolicyFilesButton_SelectedFilesTextBox.Text += file + Environment.NewLine;
				}
			}
		}
	}



}
