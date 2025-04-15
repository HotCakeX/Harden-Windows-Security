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
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using AppControlManager.CustomUIElements;
using AppControlManager.Main;
using AppControlManager.MicrosoftGraph;
using AppControlManager.Others;
using AppControlManager.SiPolicy;
using AppControlManager.SiPolicyIntel;
using AppControlManager.ViewModels;
using CommunityToolkit.WinUI;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

/// <summary>
/// DeploymentPage manages the deployment of XML and CIP files, including signing and Intune integration. It handles
/// user interactions for file selection and deployment status updates.
/// </summary>
internal sealed partial class DeploymentPage : Page, Sidebar.IAnimatedIconsManager, INotifyPropertyChanged
{

	public event PropertyChangedEventHandler? PropertyChanged;

	private ViewModel ViewModelMSGraph { get; } = App.AppHost.Services.GetRequiredService<ViewModel>();
	private AppSettings.Main AppSettings { get; } = App.AppHost.Services.GetRequiredService<AppSettings.Main>();
	private DeploymentVM ViewModel { get; } = App.AppHost.Services.GetRequiredService<DeploymentVM>();


	#region ✡️✡️✡️✡️✡️✡️✡️ MICROSOFT GRAPH IMPLEMENTATION DETAILS ✡️✡️✡️✡️✡️✡️✡️


	/// <summary>
	/// When online features are enabled, this method will enable the relevant buttons and performs extra necessary actions
	/// </summary>
	/// <param name="on"></param>
	private void UpdateButtonsStates(bool on)
	{
		// Enable the options of a valid value is set as Active Account
		deployToIntune = on;
		IntuneGroupsListView.IsEnabled = on;
		RefreshIntuneGroupsButton.IsEnabled = on;
		ViewModel.LocalOnlineStatusText = on ? "Cloud Deployment is Currently Active" : "Local Deployment is Currently Active";

		// If online features are turned off, clear the list of Intune groups
		if (!on)
		{
			ViewModel.GroupNamesCollection.Clear();
		}
	}

	internal readonly AuthenticationCompanion AuthCompanionCLS;

	#endregion ✡️✡️✡️✡️✡️✡️✡️ MICROSOFT GRAPH IMPLEMENTATION DETAILS ✡️✡️✡️✡️✡️✡️✡️


	// HashSets to store user input selected files
	private readonly HashSet<string> XMLFiles = [];
	private readonly HashSet<string> SignedXMLFiles = [];
	private readonly HashSet<string> CIPFiles = [];

	// When true, policies will be deployed to Intune instead of locally
	private bool deployToIntune;

	/// <summary>
	/// Initializes a new instance of the DeploymentPage class. Disables the DeploySignedXMLButton if the system is older
	/// than Windows 11 24H2.
	/// </summary>
	internal DeploymentPage()
	{
		this.InitializeComponent();

		this.NavigationCacheMode = NavigationCacheMode.Required;

		if (GlobalVars.IsOlderThan24H2)
		{
			DeploySignedXMLButton.IsEnabled = false;
			DeploySignedXMLButtonContentTextBlock.Text = GlobalVars.Rizz.GetString("RequiresWindows1124H2");
		}

		this.DataContext = this;

		AuthCompanionCLS = new(UpdateButtonsStates, new InfoBarSettings(
			() => ViewModel.MainInfoBarVisibility, value => ViewModel.MainInfoBarVisibility = value,
			() => ViewModel.MainInfoBarIsOpen, value => ViewModel.MainInfoBarIsOpen = value,
			() => ViewModel.MainInfoBarMessage, value => ViewModel.MainInfoBarMessage = value,
			() => ViewModel.MainInfoBarSeverity, value => ViewModel.MainInfoBarSeverity = value,
			() => ViewModel.MainInfoBarIsClosable, value => ViewModel.MainInfoBarIsClosable = value), AuthenticationContext.Intune);


		ViewModelMSGraph.AuthenticatedAccounts.CollectionChanged += AuthCompanionCLS.AuthenticatedAccounts_CollectionChanged;
	}


	#region Augmentation Interface

	private string? unsignedBasePolicyPathFromSidebar;

	/// <summary>
	/// Controls the visibility of button icons and manages their content and event handlers based on the provided
	/// visibility state.
	/// </summary>
	/// <param name="visibility">Determines the visibility state for the button icons and sidebar buttons.</param>
	/// <param name="unsignedBasePolicyPath">Stores the path for the unsigned policy from the sidebar into a local variable.</param>
	/// <param name="button1">Sets the visibility and content for the first sidebar button.</param>
	/// <param name="button2">Sets the visibility and content for the second sidebar button.</param>
	/// <param name="button3">Sets the visibility for the third sidebar button, though it is not used for content assignment.</param>
	/// <param name="button4">Sets the visibility for the fourth sidebar button, though it is not used for content assignment.</param>
	/// <param name="button5">Sets the visibility for the fifth sidebar button, though it is not used for content assignment.</param>
	public void SetVisibility(Visibility visibility, string? unsignedBasePolicyPath, Button? button1, Button? button2, Button? button3, Button? button4, Button? button5)
	{

		ArgumentNullException.ThrowIfNull(button1);
		ArgumentNullException.ThrowIfNull(button2);

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
	private async void DeployUnsignedXMLButton_Click()
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


			ViewModel.MainInfoBarVisibility = Visibility.Visible;
			ViewModel.MainInfoBarIsOpen = true;
			ViewModel.MainInfoBarMessage = GlobalVars.Rizz.GetString("DeployingXMLFiles") + XMLFiles.Count + GlobalVars.Rizz.GetString("UnsignedXMLFiles");
			ViewModel.MainInfoBarSeverity = InfoBarSeverity.Informational;
			ViewModel.MainInfoBarIsClosable = false;


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

					string randomString = Guid.CreateVersion7().ToString("N");

					string xmlFileName = Path.GetFileName(file);

					string CIPFilePath = Path.Combine(stagingArea.FullName, $"{xmlFileName}-{randomString}.cip");

					_ = DispatcherQueue.TryEnqueue(() =>
					{
						ViewModel.MainInfoBarMessage = GlobalVars.Rizz.GetString("DeployingXMLFile") + file + "'";
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

			ViewModel.MainInfoBarSeverity = InfoBarSeverity.Error;
			ViewModel.MainInfoBarMessage = GlobalVars.Rizz.GetString("DeploymentError");

			throw;
		}
		finally
		{
			if (!errorsOccurred)
			{
				ViewModel.MainInfoBarSeverity = InfoBarSeverity.Success;
				ViewModel.MainInfoBarMessage = GlobalVars.Rizz.GetString("DeploymentSuccess");

				// Clear the lists at the end if no errors occurred
				XMLFiles.Clear();

				BrowseForXMLPolicyFilesButton_SelectedFilesTextBox.Text = null;
			}

			// Re-enable all the deploy buttons
			DeployUnsignedXMLButton.IsEnabled = true;
			DeployCIPButton.IsEnabled = true;
			DeploySignedXMLButton.IsEnabled = true;

			MainProgressRing.Visibility = Visibility.Collapsed;
			ViewModel.MainInfoBarIsClosable = true;
		}
	}


	/// <summary>
	/// Deploy Signed XML files button
	/// </summary>
	private async void DeploySignedXMLButton_Click()
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

			ViewModel.MainInfoBarVisibility = Visibility.Visible;
			ViewModel.MainInfoBarIsOpen = true;
			ViewModel.MainInfoBarMessage = GlobalVars.Rizz.GetString("DeployingSignedXMLFiles") + SignedXMLFiles.Count + GlobalVars.Rizz.GetString("SignedXMLFiles");
			ViewModel.MainInfoBarSeverity = InfoBarSeverity.Informational;
			ViewModel.MainInfoBarIsClosable = false;

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
						ViewModel.MainInfoBarMessage = (SignOnlyNoDeployToggleSwitchStatus ? "Currently Signing XML file:" : GlobalVars.Rizz.GetString("DeployingXMLFile")) + file + "'";
					});


					// Add certificate's details to the policy
					SiPolicy.SiPolicy policyObject = AddSigningDetails.Add(file, CertPath);

					// Remove the unsigned policy rule option from the policy
					CiRuleOptions.Set(filePath: file, rulesToRemove: [OptionType.EnabledUnsignedSystemIntegrityPolicy]);

					// Define the path for the CIP file
					string randomString = Guid.CreateVersion7().ToString("N");
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

			ViewModel.MainInfoBarSeverity = InfoBarSeverity.Error;
			ViewModel.MainInfoBarMessage = GlobalVars.Rizz.GetString("DeploymentError");

			throw;
		}
		finally
		{
			if (!errorsOccurred)
			{
				ViewModel.MainInfoBarSeverity = InfoBarSeverity.Success;
				ViewModel.MainInfoBarMessage = SignOnlyNoDeployToggleSwitchStatus ? "Successfully created signed CIP files for all of the selected XML files." : GlobalVars.Rizz.GetString("SignedDeploymentSuccess");

				// Clear the lists at the end if no errors occurred
				SignedXMLFiles.Clear();

				BrowseForSignedXMLPolicyFilesButton_SelectedFilesTextBox.Text = null;
			}

			// Re-enable all the deploy buttons
			DeployUnsignedXMLButton.IsEnabled = true;
			DeployCIPButton.IsEnabled = true;
			DeploySignedXMLButton.IsEnabled = true;

			MainProgressRing.Visibility = Visibility.Collapsed;
			ViewModel.MainInfoBarIsClosable = true;
		}
	}


	/// <summary>
	/// Deploy CIP files button
	/// </summary>
	private async void DeployCIPButton_Click()
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

			ViewModel.MainInfoBarVisibility = Visibility.Visible;
			ViewModel.MainInfoBarIsOpen = true;
			ViewModel.MainInfoBarMessage = GlobalVars.Rizz.GetString("DeployingCIPFiles") + CIPFiles.Count + GlobalVars.Rizz.GetString("CIPFiles");
			ViewModel.MainInfoBarSeverity = InfoBarSeverity.Informational;
			ViewModel.MainInfoBarIsClosable = false;

			MainProgressRing.Visibility = Visibility.Visible;

			// Deploy the selected CIP files
			await Task.Run(async () =>
			{
				foreach (string file in CIPFiles)
				{
					_ = DispatcherQueue.TryEnqueue(() =>
					{
						ViewModel.MainInfoBarMessage = GlobalVars.Rizz.GetString("DeployingCIPFile") + file + "'";
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

			ViewModel.MainInfoBarSeverity = InfoBarSeverity.Error;
			ViewModel.MainInfoBarMessage = GlobalVars.Rizz.GetString("DeploymentError");

			throw;
		}
		finally
		{
			if (!errorsOccurred)
			{
				ViewModel.MainInfoBarSeverity = InfoBarSeverity.Success;
				ViewModel.MainInfoBarMessage = GlobalVars.Rizz.GetString("CIPDeploymentSuccess");

				// Clear the list at the end if no errors occurred
				CIPFiles.Clear();

				BrowseForCIPBinaryFilesButton_SelectedFilesTextBox.Text = null;
			}

			DeployUnsignedXMLButton.IsEnabled = true;
			DeployCIPButton.IsEnabled = true;
			DeploySignedXMLButton.IsEnabled = true;

			MainProgressRing.Visibility = Visibility.Collapsed;
			ViewModel.MainInfoBarIsClosable = true;
		}
	}


	/// <summary>
	/// Event handler for browse button - Unsigned XML files
	/// </summary>
	private void BrowseForXMLPolicyFilesButton_Click()
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
	private void BrowseForCIPBinaryFilesButton_Click()
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
	private void BrowseForCIPBinaryFilesButton_Flyout_Clear_Click()
	{
		BrowseForCIPBinaryFilesButton_SelectedFilesTextBox.Text = null;
		CIPFiles.Clear();
	}


	/// <summary>
	/// Clear button for the unsigned files deployment button flyout
	/// </summary>
	private void BrowseForXMLPolicyFilesButton_Flyout_Clear_Click()
	{
		BrowseForXMLPolicyFilesButton_SelectedFilesTextBox.Text = null;
		XMLFiles.Clear();
	}


	/// <summary>
	/// Clear button for the Signed files deployment button flyout
	/// </summary>
	private void BrowseForSignedXMLPolicyFilesButton_Flyout_Clear_Click()
	{
		BrowseForSignedXMLPolicyFilesButton_SelectedFilesTextBox.Text = null;
		SignedXMLFiles.Clear();
	}


	/// <summary>
	/// Event handler for browse button - Signed XML files
	/// </summary>
	private void BrowseForSignedXMLPolicyFilesButton_Click()
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
	/// Handles the click event for the Refresh Intune Groups button. It fetches groups from Microsoft Graph and updates
	/// the ListView with group names.
	/// </summary>
	private async void RefreshIntuneGroupsButton_Click()
	{
		try
		{
			RefreshIntuneGroupsButton.IsEnabled = false;

			Dictionary<string, string> groups = await MicrosoftGraph.Main.FetchGroups(AuthCompanionCLS.CurrentActiveAccount);

			ViewModel.GroupNamesCollection.Clear();

			// Update the ListView with group names
			foreach (KeyValuePair<string, string> item in groups)
			{
				ViewModel.GroupNamesCollection.Add(new IntuneGroupItemListView(item.Key, item.Value));
			}
		}
		finally
		{
			RefreshIntuneGroupsButton.IsEnabled = true;
		}
	}


	/// <summary>
	/// Deploys a specified file to Intune using a given policy ID and optionally an XML file for additional settings.
	/// </summary>
	/// <param name="file">Specifies the file to be uploaded to Intune.</param>
	/// <param name="policyID">Identifies the policy under which the file will be deployed.</param>
	/// <param name="xmlFile">Provides an optional XML file that may contain additional configuration settings.</param>
	/// <returns>This method does not return a value.</returns>
	private async Task DeployToIntunePrivate(string file, string policyID, string? xmlFile = null)
	{
		// ID(s) of the groups to assign the policy to
		List<string> groupIDs = [];

		await DispatcherQueue.EnqueueAsync(() =>
		{
			foreach (var item in IntuneGroupsListView.SelectedItems)
			{
				// Get the group name
				IntuneGroupItemListView _item = (IntuneGroupItemListView)item;

				groupIDs.Add(_item.GroupID);
			}
		});

		// Name of the policy that will be uploaded
		string? policyName = null;

		// The description text for the Intune portal
		// It will contain all of the information related to the policy
		string descriptionText = null!;

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


				// Construct an instance of the class in order to serialize it into JSON string for upload to Intune
				CiPolicyInfo policy = new(
					policyID: policyObj.PolicyID,
					basePolicyID: policyObj.BasePolicyID,
					friendlyName: policyName,
					version: null,
					versionString: policyObj.VersionEx,
					isSystemPolicy: false,
					isSignedPolicy: !policyObj.Rules.Any(x => x.Item == OptionType.EnabledUnsignedSystemIntegrityPolicy),
					isOnDisk: false,
					isEnforced: true,
					isAuthorized: true,
					policyOptions: policyObj.Rules.Select(x => ((int)x.Item).ToString()).ToList() // Only use the numbers of each rule to save characters since the string limit is 1000 characters for the Description section of Custom policies
				);

				descriptionText = CiPolicyInfo.ToJson(policy);

			}

		});

		await MicrosoftGraph.Main.UploadPolicyToIntune(AuthCompanionCLS.CurrentActiveAccount, file, groupIDs, policyName, policyID, descriptionText);
	}



	private void BrowseForXMLPolicyFilesButton_RightTapped()
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
	private void BrowseForXMLPolicesButton_Click()
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


	/// <summary>
	/// Handles the click event for converting XML files to CIP format.
	/// </summary>
	private async void ConvertXMLToCIPButton_Click()
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
						ViewModel.MainInfoBarVisibility = Visibility.Visible;
						ViewModel.MainInfoBarIsOpen = true;
						ViewModel.MainInfoBarMessage = $"Converting {file} to XML";
						ViewModel.MainInfoBarSeverity = InfoBarSeverity.Informational;
						ViewModel.MainInfoBarIsClosable = false;
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

			ViewModel.MainInfoBarSeverity = InfoBarSeverity.Error;
			ViewModel.MainInfoBarMessage = $"There was a problem converting the XML files to CIP: {ex.Message}";
		}
		finally
		{
			if (!ErrorsOccurred)
			{
				ViewModel.MainInfoBarSeverity = InfoBarSeverity.Success;
				ViewModel.MainInfoBarMessage = "Successfully converted all of the selected XML files to CIP binaries";
			}

			ViewModel.MainInfoBarIsClosable = true;
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
	private void BrowseForXMLPolicesButton_Flyout_Clear_Click()
	{
		XMLFilesToConvertToCIP.Clear();
	}


	/// <summary>
	/// Event handler for the settings card to toggle the button
	/// </summary>
	private void SignOnlyNoDeploySettingsCard_Click()
	{
		SignOnlyNoDeployToggleSwitch.IsOn = !SignOnlyNoDeployToggleSwitch.IsOn;

		DeploySignedXMLButtonContentTextBlock.Text = SignOnlyNoDeployToggleSwitch.IsOn ? "Sign Only" : "Deploy";

		DeploySignedXMLButtonFontIcon.Glyph = SignOnlyNoDeployToggleSwitch.IsOn ? "\uF572" : "\uE8B6";
	}

	/// <summary>
	/// Event handler for the toggle button that determines whether policies should be signed + deployed or signed only
	/// </summary>
	private void SignOnlyNoDeployToggleSwitch_Toggled()
	{
		DeploySignedXMLButtonContentTextBlock.Text = SignOnlyNoDeployToggleSwitch.IsOn ? "Sign Only" : "Deploy";

		DeploySignedXMLButtonFontIcon.Glyph = SignOnlyNoDeployToggleSwitch.IsOn ? "\uF572" : "\uE8B6";
	}




	/// <summary>
	/// Sets the property and raises the PropertyChanged event if the value has changed.
	/// This also prevents infinite loops where a property raises OnPropertyChanged which could trigger an update in the UI, and the UI might call set again, leading to an infinite loop.
	/// </summary>
	/// <typeparam name="T"></typeparam>
	/// <param name="currentValue"></param>
	/// <param name="newValue"></param>
	/// <param name="setter"></param>
	/// <param name="propertyName"></param>
	/// <returns></returns>
	private bool SetProperty<T>(T currentValue, T newValue, Action<T> setter, [CallerMemberName] string? propertyName = null)
	{
		if (EqualityComparer<T>.Default.Equals(currentValue, newValue))
			return false;
		setter(newValue);
		OnPropertyChanged(propertyName);
		return true;
	}


	private void OnPropertyChanged(string? propertyName)
	{
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
	}
}
