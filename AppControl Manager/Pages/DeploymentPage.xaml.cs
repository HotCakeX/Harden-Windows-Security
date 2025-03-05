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
using AppControlManager.CustomUIElements;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.SiPolicy;
using AppControlManager.SiPolicyIntel;
using CommunityToolkit.WinUI;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

public sealed partial class DeploymentPage : Page, Sidebar.IAnimatedIconsManager
{
	// HashSets to store user input selected files
	private readonly HashSet<string> XMLFiles = [];
	private readonly HashSet<string> SignedXMLFiles = [];
	private readonly HashSet<string> CIPFiles = [];

	// When true, policies will be deployed to Intune instead of locally
	private bool deployToIntune;

	public DeploymentPage()
	{
		this.InitializeComponent();

		this.NavigationCacheMode = NavigationCacheMode.Required;

		if (GlobalVars.IsOlderThan24H2)
		{
			DeploySignedXMLButton.IsEnabled = false;
			DeploySignedXMLButtonContentTextBlock.Text = GlobalVars.Rizz.GetString("RequiresWindows1124H2");
		}
	}


	#region Augmentation Interface

	private string? unsignedBasePolicyPathFromSidebar;

	// Implement the SetVisibility method required by IAnimatedIconsManager
	public void SetVisibility(Visibility visibility, string? unsignedBasePolicyPath, Button button1, Button button2, Button button3, Button button4, Button button5)
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
			button1.Content = GlobalVars.Rizz.GetString("DeployUnsignedPolicy");
			button2.Content = GlobalVars.Rizz.GetString("DeploySignedPolicy");

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

			BrowseForXMLPolicyFilesButton_Flyout.ShowAt(BrowseForXMLPolicyFilesButton);
		}
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

			BrowseForSignedXMLPolicyFilesButton_Flyout.ShowAt(BrowseForSignedXMLPolicyFilesButton);
		}
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
			StatusInfoBar.Message = GlobalVars.Rizz.GetString("DeployingXMLFiles") + XMLFiles.Count + GlobalVars.Rizz.GetString("UnsignedXMLFiles");
			StatusInfoBar.Severity = InfoBarSeverity.Informational;
			StatusInfoBar.IsClosable = false;

			MainProgressRing.Visibility = Visibility.Visible;

			// Deploy the selected files
			await Task.Run(async () =>
			{

				DirectoryInfo stagingArea = StagingArea.NewStagingArea("UnsignedDeployments");

				// Convert and then deploy each XML file
				foreach (string file in XMLFiles)
				{

					// Instantiate the policy
					SiPolicy.SiPolicy policyObject = Management.Initialize(file, null);

					if (!policyObject.Rules.Any(rule => rule.Item is OptionType.EnabledUnsignedSystemIntegrityPolicy))
					{
						throw new InvalidOperationException(GlobalVars.Rizz.GetString("SignedPolicyError") + file + "'");
					}

					string randomString = GUIDGenerator.GenerateUniqueGUID();

					string xmlFileName = Path.GetFileName(file);

					string CIPFilePath = Path.Combine(stagingArea.FullName, $"{xmlFileName}-{randomString}.cip");

					_ = DispatcherQueue.TryEnqueue(() =>
					{
						StatusInfoBar.Message = GlobalVars.Rizz.GetString("DeployingXMLFile") + file + "'";
					});

					// Convert the XML file to CIP
					PolicyToCIPConverter.Convert(file, CIPFilePath);

					if (deployToIntune)
					{
						await DeployToIntunePrivate(CIPFilePath, policyObject.PolicyID, file);

						// Delete the CIP file after deployment
						File.Delete(CIPFilePath);
					}
					else
					{
						// Deploy the CIP file locally
						CiToolHelper.UpdatePolicy(CIPFilePath);

						// Delete the CIP file after deployment
						File.Delete(CIPFilePath);

						// Deploy the AppControlManager supplemental policy
						if (SupplementalForSelf.IsEligible(policyObject, file))
							SupplementalForSelf.Deploy(stagingArea.FullName, policyObject.PolicyID);
					}
				}
			});
		}

		catch
		{
			errorsOccurred = true;

			StatusInfoBar.Severity = InfoBarSeverity.Error;
			StatusInfoBar.Message = GlobalVars.Rizz.GetString("DeploymentError");

			throw;
		}
		finally
		{
			if (!errorsOccurred)
			{
				StatusInfoBar.Severity = InfoBarSeverity.Success;
				StatusInfoBar.Message = GlobalVars.Rizz.GetString("DeploymentSuccess");

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

		App.CurrentlyOpenContentDialog = customDialog;

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

		// Get the status of the toggle button on the UI that defines whether we should only sign or deploy too
		bool SignOnlyNoDeployToggleSwitchStatus = SignOnlyNoDeployToggleSwitch.IsOn;

		try
		{
			// Disable all the deployment buttons during main operation
			DeployUnsignedXMLButton.IsEnabled = false;
			DeployCIPButton.IsEnabled = false;
			DeploySignedXMLButton.IsEnabled = false;

			StatusInfoBar.Visibility = Visibility.Visible;
			StatusInfoBar.IsOpen = true;
			StatusInfoBar.Message = GlobalVars.Rizz.GetString("DeployingSignedXMLFiles") + SignedXMLFiles.Count + GlobalVars.Rizz.GetString("SignedXMLFiles");
			StatusInfoBar.Severity = InfoBarSeverity.Informational;
			StatusInfoBar.IsClosable = false;

			MainProgressRing.Visibility = Visibility.Visible;

			// Deploy the selected files
			await Task.Run(async () =>
			{

				DirectoryInfo stagingArea = StagingArea.NewStagingArea("SignedDeployments");

				// Convert and then deploy each XML file
				foreach (string file in SignedXMLFiles)
				{

					_ = DispatcherQueue.TryEnqueue(() =>
					{
						StatusInfoBar.Message = (SignOnlyNoDeployToggleSwitchStatus ? "Currently Signing XML file:" : GlobalVars.Rizz.GetString("DeployingXMLFile")) + file + "'";
					});


					// Add certificate's details to the policy
					SiPolicy.SiPolicy policyObject = AddSigningDetails.Add(file, CertPath);

					// Remove the unsigned policy rule option from the policy
					CiRuleOptions.Set(filePath: file, rulesToRemove: [OptionType.EnabledUnsignedSystemIntegrityPolicy]);

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

					// If the SignOnlyNoDeployToggleSwitch is on, don't deploy the policy, only create signed CIP
					if (SignOnlyNoDeployToggleSwitchStatus)
					{
						File.Move(CIPFilePath, Path.Combine(GlobalVars.UserConfigDir, $"{Path.GetFileNameWithoutExtension(file)}.CIP"), true);
					}
					else
					{
						if (deployToIntune)
						{
							await DeployToIntunePrivate(CIPFilePath, policyObject.PolicyID, file);
						}
						else
						{

							// Get all of the deployed base and supplemental policies on the system
							List<CiPolicyInfo> policies = CiToolHelper.GetPolicies(false, true, true);

							CiPolicyInfo? possibleAlreadyDeployedUnsignedVersion = policies.
							FirstOrDefault(x => string.Equals(policyObject.PolicyID.Trim('{', '}'), x.PolicyID, StringComparison.OrdinalIgnoreCase));

							if (possibleAlreadyDeployedUnsignedVersion is not null)
							{
								Logger.Write(GlobalVars.Rizz.GetString("PolicyConflictMessage") + possibleAlreadyDeployedUnsignedVersion.PolicyID + GlobalVars.Rizz.GetString("RemovingPolicy"));

								CiToolHelper.RemovePolicy(possibleAlreadyDeployedUnsignedVersion.PolicyID!);
							}

							// Sign and deploy the required AppControlManager supplemental policy
							if (SupplementalForSelf.IsEligible(policyObject, file))
								SupplementalForSelf.DeploySigned(policyObject.PolicyID, CertPath, SignToolPath, CertCN);

							// Deploy the CIP file locally
							CiToolHelper.UpdatePolicy(CIPFilePath);
						}
					}
				}
			});
		}

		catch
		{
			errorsOccurred = true;

			StatusInfoBar.Severity = InfoBarSeverity.Error;
			StatusInfoBar.Message = GlobalVars.Rizz.GetString("DeploymentError");

			throw;
		}
		finally
		{
			if (!errorsOccurred)
			{
				StatusInfoBar.Severity = InfoBarSeverity.Success;
				StatusInfoBar.Message = SignOnlyNoDeployToggleSwitchStatus ? "Successfully created signed CIP files for all of the selected XML files." : GlobalVars.Rizz.GetString("SignedDeploymentSuccess");

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
			StatusInfoBar.Message = GlobalVars.Rizz.GetString("DeployingCIPFiles") + CIPFiles.Count + GlobalVars.Rizz.GetString("CIPFiles");
			StatusInfoBar.Severity = InfoBarSeverity.Informational;
			StatusInfoBar.IsClosable = false;

			MainProgressRing.Visibility = Visibility.Visible;

			// Deploy the selected CIP files
			await Task.Run(async () =>
			{
				foreach (string file in CIPFiles)
				{
					_ = DispatcherQueue.TryEnqueue(() =>
					{
						StatusInfoBar.Message = GlobalVars.Rizz.GetString("DeployingCIPFile") + file + "'";
					});

					string randomPolicyID = Guid.CreateVersion7().ToString().ToUpperInvariant();

					if (deployToIntune)
					{
						await DeployToIntunePrivate(file, randomPolicyID, null);
					}
					else
					{
						// Deploy the CIP file
						CiToolHelper.UpdatePolicy(file);
					}

				}
			});
		}

		catch
		{
			errorsOccurred = true;

			StatusInfoBar.Severity = InfoBarSeverity.Error;
			StatusInfoBar.Message = GlobalVars.Rizz.GetString("DeploymentError");

			throw;
		}
		finally
		{
			if (!errorsOccurred)
			{
				StatusInfoBar.Severity = InfoBarSeverity.Success;
				StatusInfoBar.Message = GlobalVars.Rizz.GetString("CIPDeploymentSuccess");

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


	/// <summary>
	/// Event handler for the SignIn button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void IntuneSignInButton_Click(object sender, RoutedEventArgs e)
	{

		bool signInSuccessful = false;

		try
		{
			StatusInfoBar.Visibility = Visibility.Visible;
			StatusInfoBar.IsOpen = true;
			StatusInfoBar.Message = GlobalVars.Rizz.GetString("SigningIntoIntune");
			StatusInfoBar.Severity = InfoBarSeverity.Informational;
			StatusInfoBar.IsClosable = false;

			IntuneCancelSignInButton.IsEnabled = true;

			IntuneSignInButton.IsEnabled = false;

			await MicrosoftGraph.SignIn(MicrosoftGraph.AuthenticationContext.Intune);

			StatusInfoBar.Message = GlobalVars.Rizz.GetString("IntuneSignInSuccess");
			StatusInfoBar.Severity = InfoBarSeverity.Success;

			deployToIntune = true;

			LocalIntuneStatusTextBox.Text = GlobalVars.Rizz.GetString("CloudDeploymentActive");

			// Enable the sign out button
			IntuneSignOutButton.IsEnabled = true;

			signInSuccessful = true;

			IntuneGroupsComboBox.IsEnabled = true;
			RefreshIntuneGroupsButton.IsEnabled = true;
		}

		catch (OperationCanceledException)
		{
			signInSuccessful = false;
			Logger.Write(GlobalVars.Rizz.GetString("IntuneSignInCancelled"));
			StatusInfoBar.Message = GlobalVars.Rizz.GetString("IntuneSignInCancelledMessage");
			StatusInfoBar.Severity = InfoBarSeverity.Warning;
		}

		catch (Exception ex)
		{
			StatusInfoBar.Message = GlobalVars.Rizz.GetString("IntuneSignInError") + ex.Message;
			StatusInfoBar.Severity = InfoBarSeverity.Error;

			throw;
		}

		finally
		{
			// If sign in wasn't successful, keep the button enabled
			if (!signInSuccessful)
			{
				IntuneSignInButton.IsEnabled = true;
			}

			StatusInfoBar.IsClosable = true;

			IntuneCancelSignInButton.IsEnabled = false;
		}

	}


	private async void IntuneSignOutButton_Click(object sender, RoutedEventArgs e)
	{

		bool signOutSuccessful = false;

		try
		{
			StatusInfoBar.Visibility = Visibility.Visible;
			StatusInfoBar.IsOpen = true;
			StatusInfoBar.Message = GlobalVars.Rizz.GetString("SigningOutOfIntune");
			StatusInfoBar.Severity = InfoBarSeverity.Informational;
			StatusInfoBar.IsClosable = false;

			IntuneSignOutButton.IsEnabled = false;

			await MicrosoftGraph.SignOut(MicrosoftGraph.AuthenticationContext.Intune);

			signOutSuccessful = true;

			// Enable the Sign in button
			IntuneSignInButton.IsEnabled = true;

			StatusInfoBar.Message = GlobalVars.Rizz.GetString("IntuneSignOutSuccess");
			StatusInfoBar.Severity = InfoBarSeverity.Success;

			deployToIntune = false;
			IntuneGroupsComboBox.IsEnabled = false;
			RefreshIntuneGroupsButton.IsEnabled = false;

			LocalIntuneStatusTextBox.Text = GlobalVars.Rizz.GetString("LocalDeploymentActive");
		}
		catch (Exception ex)
		{
			StatusInfoBar.Message = GlobalVars.Rizz.GetString("IntuneSignOutError") + ex.Message;
			StatusInfoBar.Severity = InfoBarSeverity.Error;

			throw;
		}
		finally
		{
			// If sign out wasn't successful, keep the button enabled
			if (!signOutSuccessful)
			{
				IntuneSignOutButton.IsEnabled = true;
			}

			StatusInfoBar.IsClosable = true;
		}
	}


	private async void RefreshIntuneGroupsButton_Click(object sender, RoutedEventArgs e)
	{
		await MicrosoftGraph.FetchGroups();
		Dictionary<string, string> groups = MicrosoftGraph.GetGroups();

		// Update the ComboBox with group names
		IntuneGroupsComboBox.ItemsSource = groups.Keys;
		IntuneGroupsComboBox.SelectedIndex = 0;
	}


	private async Task DeployToIntunePrivate(string file, string policyID, string? xmlFile = null)
	{
		string? groupID = null;

		await DispatcherQueue.EnqueueAsync(() =>
		{
			groupID = IntuneGroupsComboBox.SelectedItem as string;

		});

		string? policyName = null;

		await Task.Run(() =>
		{
			if (xmlFile is not null)
			{

				SiPolicy.SiPolicy policyObj = Management.Initialize(xmlFile, null);

				// Finding the policy name in the settings
				Setting? nameSetting = policyObj.Settings.FirstOrDefault(x =>
					string.Equals(x.Provider, "PolicyInfo", StringComparison.OrdinalIgnoreCase) &&
					string.Equals(x.Key, "Information", StringComparison.OrdinalIgnoreCase) &&
					string.Equals(x.ValueName, "Name", StringComparison.OrdinalIgnoreCase));

				if (nameSetting is not null)
				{
					policyName = nameSetting.Value.Item.ToString();
				}
			}

		});

		await MicrosoftGraph.UploadPolicyToIntune(file, groupID, policyName, policyID);
	}


	/// <summary>
	/// Event handler for the Cancel Sign In button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void IntuneCancelSignInButton_Click(object sender, RoutedEventArgs e)
	{
		MicrosoftGraph.CancelSignIn();
	}

	private void BrowseForXMLPolicyFilesButton_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!BrowseForXMLPolicyFilesButton_Flyout.IsOpen)
			BrowseForXMLPolicyFilesButton_Flyout.ShowAt(BrowseForXMLPolicyFilesButton);
	}

	private void BrowseForXMLPolicyFilesButton_Holding(object sender, HoldingRoutedEventArgs e)
	{
		if (e.HoldingState is HoldingState.Started)
			if (!BrowseForXMLPolicyFilesButton_Flyout.IsOpen)
				BrowseForXMLPolicyFilesButton_Flyout.ShowAt(BrowseForXMLPolicyFilesButton);
	}

	private void BrowseForSignedXMLPolicyFilesButton_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!BrowseForSignedXMLPolicyFilesButton_Flyout.IsOpen)
			BrowseForSignedXMLPolicyFilesButton_Flyout.ShowAt(BrowseForSignedXMLPolicyFilesButton);
	}

	private void BrowseForSignedXMLPolicyFilesButton_Holding(object sender, HoldingRoutedEventArgs e)
	{
		if (e.HoldingState is HoldingState.Started)
			if (!BrowseForSignedXMLPolicyFilesButton_Flyout.IsOpen)
				BrowseForSignedXMLPolicyFilesButton_Flyout.ShowAt(BrowseForSignedXMLPolicyFilesButton);
	}

	private void BrowseForCIPBinaryFilesButton_Holding(object sender, HoldingRoutedEventArgs e)
	{
		if (e.HoldingState is HoldingState.Started)
			if (!BrowseForCIPBinaryFilesButton_Flyout.IsOpen)
				BrowseForCIPBinaryFilesButton_Flyout.ShowAt(BrowseForCIPBinaryFilesButton);
	}

	private void BrowseForCIPBinaryFilesButton_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!BrowseForCIPBinaryFilesButton_Flyout.IsOpen)
			BrowseForCIPBinaryFilesButton_Flyout.ShowAt(BrowseForCIPBinaryFilesButton);
	}


	private readonly HashSet<string> XMLFilesToConvertToCIP = [];

	/// <summary>
	/// Event handler for the button to convert XML files to CIP binary files
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void BrowseForXMLPolicesButton_Click(object sender, RoutedEventArgs e)
	{
		List<string>? selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (selectedFiles is { Count: > 0 })
		{
			foreach (string file in selectedFiles)
			{
				if (XMLFilesToConvertToCIP.Add(file))
				{
					// Append the new file to the TextBox, followed by a newline
					BrowseForXMLPolicesButton_SelectedFilesTextBox.Text += file + Environment.NewLine;
				}
			}
		}
	}




	private void BrowseForXMLPolicesButton_Holding(object sender, HoldingRoutedEventArgs e)
	{
		if (e.HoldingState is HoldingState.Started)
			if (!BrowseForXMLPolicesButton_Flyout.IsOpen)
				BrowseForXMLPolicesButton_Flyout.ShowAt(BrowseForXMLPolicesButton);
	}

	private void BrowseForXMLPolicesButton_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!BrowseForXMLPolicesButton_Flyout.IsOpen)
			BrowseForXMLPolicesButton_Flyout.ShowAt(BrowseForXMLPolicesButton);
	}


	private async void ConvertXMLToCIPButton_Click(object sender, RoutedEventArgs e)
	{

		ConvertXMLToCIPButtonTeachingTip.IsOpen = false;

		if (XMLFilesToConvertToCIP.Count is 0)
		{
			ConvertXMLToCIPButtonTeachingTip.IsOpen = true;
			return;
		}

		bool ErrorsOccurred = false;

		try
		{

			DeployUnsignedXMLPolicyFilesSettingsCard.IsEnabled = false;
			DeploySignedXMLPolicyFilesSettingsExpander.IsEnabled = false;
			DeployCIPFilesSettingsCard.IsEnabled = false;
			ConvertXMLToCIPButton.IsEnabled = false;

			await Task.Run(() =>
			{
				foreach (string file in XMLFilesToConvertToCIP)
				{

					_ = DispatcherQueue.TryEnqueue(() =>
					{
						StatusInfoBar.Visibility = Visibility.Visible;
						StatusInfoBar.IsOpen = true;
						StatusInfoBar.Message = $"Converting {file} to XML";
						StatusInfoBar.Severity = InfoBarSeverity.Informational;
						StatusInfoBar.IsClosable = false;
						MainProgressRing.Visibility = Visibility.Visible;
					});

					string XMLSavePath = Path.Combine(GlobalVars.UserConfigDir, $"{Path.GetFileNameWithoutExtension(file)}.CIP");

					if (File.Exists(XMLSavePath))
					{
						File.Delete(XMLSavePath);
					}

					// Convert the XML file to CIP
					PolicyToCIPConverter.Convert(file, XMLSavePath);
				}
			});
		}
		catch (Exception ex)
		{
			ErrorsOccurred = true;

			StatusInfoBar.Severity = InfoBarSeverity.Error;
			StatusInfoBar.Message = $"There was a problem converting the XML files to CIP: {ex.Message}";
		}
		finally
		{
			if (!ErrorsOccurred)
			{
				StatusInfoBar.Severity = InfoBarSeverity.Success;
				StatusInfoBar.Message = "Successfully converted all of the selected XML files to CIP binaries";
			}

			StatusInfoBar.IsClosable = true;
			MainProgressRing.Visibility = Visibility.Collapsed;

			DeployUnsignedXMLPolicyFilesSettingsCard.IsEnabled = true;
			DeploySignedXMLPolicyFilesSettingsExpander.IsEnabled = true;
			DeployCIPFilesSettingsCard.IsEnabled = true;
			ConvertXMLToCIPButton.IsEnabled = true;
		}

	}

	/// <summary>
	/// Event handler to clear the list of XML files that are only converted to CIP files
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void BrowseForXMLPolicesButton_Flyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		XMLFilesToConvertToCIP.Clear();
	}


	/// <summary>
	/// Event handler for the settings card to toggle the button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void SignOnlyNoDeploySettingsCard_Click(object sender, RoutedEventArgs e)
	{
		SignOnlyNoDeployToggleSwitch.IsOn = !SignOnlyNoDeployToggleSwitch.IsOn;

		DeploySignedXMLButtonContentTextBlock.Text = SignOnlyNoDeployToggleSwitch.IsOn ? "Sign Only" : "Deploy";

		DeploySignedXMLButtonFontIcon.Glyph = SignOnlyNoDeployToggleSwitch.IsOn ? "\uF572" : "\uE8B6";
	}

	/// <summary>
	/// Event handler for the toggle button that determines whether policies should be signed + deployed or signed only
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void SignOnlyNoDeployToggleSwitch_Toggled(object sender, RoutedEventArgs e)
	{
		DeploySignedXMLButtonContentTextBlock.Text = SignOnlyNoDeployToggleSwitch.IsOn ? "Sign Only" : "Deploy";

		DeploySignedXMLButtonFontIcon.Glyph = SignOnlyNoDeployToggleSwitch.IsOn ? "\uF572" : "\uE8B6";
	}

}
