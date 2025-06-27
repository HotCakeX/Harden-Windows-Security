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
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AppControlManager.CustomUIElements;
using AppControlManager.MicrosoftGraph;
using AppControlManager.Others;
using AppControlManager.SiPolicy;
using AppControlManager.SiPolicyIntel;
using AppControlManager.XMLOps;
using CommunityToolkit.WinUI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.ViewModels;

internal sealed partial class DeploymentVM : ViewModelBase, IDisposable
{
	internal ViewModelForMSGraph ViewModelMSGraph { get; } = ViewModelProvider.ViewModelForMSGraph;

	internal DeploymentVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			null, null);

		AuthCompanionCLS = new(UpdateButtonsStates, new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value), AuthenticationContext.Intune);

		ViewModelMSGraph.AuthenticatedAccounts.CollectionChanged += AuthCompanionCLS.AuthenticatedAccounts_CollectionChanged;

		if (GlobalVars.IsOlderThan24H2)
		{
			DeploySignedXMLButtonIsEnabled = false;
			DeploySignedXMLButtonContentTextBlock = GlobalVars.GetStr("RequiresWindows1124H2");
		}
		else
		{
			DeploySignedXMLButtonIsEnabled = true;
		}
	}

	internal readonly InfoBarSettings MainInfoBar;

	internal Visibility UnsignedXMLFilesLightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility SignedXMLFilesLightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	internal string LocalOnlineStatusText { get; set => SP(ref field, value); } = GlobalVars.GetStr("LocalDeploymentActive");

	/// <summary>
	/// Bound to the UI ListView and holds the Intune group Names/IDs
	/// </summary>
	internal readonly ObservableCollection<IntuneGroupItemListView> GroupNamesCollection = [];

	internal readonly UniqueStringObservableCollection XMLFiles = [];
	internal readonly UniqueStringObservableCollection SignedXMLFiles = [];
	internal readonly UniqueStringObservableCollection CIPFiles = [];
	internal readonly UniqueStringObservableCollection XMLFilesToConvertToCIP = [];

	internal readonly AuthenticationCompanion AuthCompanionCLS;

	internal bool DeploySignedXMLButtonIsEnabled { get; set => SP(ref field, value); }

	/// <summary>
	/// When true, policies will be deployed to Intune instead of locally
	/// </summary>
	internal bool DeployToIntune { get; set => SP(ref field, value); }

	/// <summary>
	/// Determines whether the UI elements are enabled or disabled.
	/// </summary>
	internal bool AreElementsEnabled { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Determines whether the online features related to Online are enabled or disabled.
	/// </summary>
	internal bool AreOnlineFeaturesEnabled { get; set => SP(ref field, value); }

	internal string DeploySignedXMLButtonContentTextBlock { get; set => SP(ref field, value); } = GlobalVars.GetStr("ButtonContentDeploy");
	internal string DeploySignedXMLButtonFontIcon { get; set => SP(ref field, value); } = "\uE8B6";

	internal bool SignOnlyNoDeployToggleSwitch
	{
		get; set
		{
			if (SP(ref field, value))
			{
				DeploySignedXMLButtonContentTextBlock = field ? GlobalVars.GetStr("ButtonContentSignOnly") : GlobalVars.GetStr("ButtonContentDeploy");

				DeploySignedXMLButtonFontIcon = field ? "\uF572" : "\uE8B6";
			}
		}
	}

	/// <summary>
	/// Controls the visibility of the Main progress bar.
	/// </summary>
	internal Visibility MainProgressBarVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	/// <summary>
	/// Event handler to clear the list of XML files that are only converted to CIP files
	/// </summary>
	internal void BrowseForXMLPolicesButton_Flyout_Clear_Click()
	{
		XMLFilesToConvertToCIP.Clear();
	}

	/// <summary>
	/// Event handler for browse button - Unsigned XML files
	/// </summary>
	internal void BrowseForXMLPolicyFilesButton_Click()
	{
		List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (selectedFiles.Count > 0)
		{
			foreach (string file in selectedFiles)
			{
				XMLFiles.Add(file);
			}
		}
	}

	/// <summary>
	/// Event handler for Browser button - CIP files
	/// </summary>
	internal void BrowseForCIPBinaryFilesButton_Click()
	{
		const string filter = "CIP file|*.cip";

		List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(filter);

		if (selectedFiles.Count > 0)
		{
			foreach (string file in selectedFiles)
			{
				CIPFiles.Add(file);
			}
		}
	}

	/// <summary>
	/// Clear button for the CIP files deployment button flyout
	/// </summary>
	internal void BrowseForCIPBinaryFilesButton_Flyout_Clear_Click()
	{
		CIPFiles.Clear();
	}

	/// <summary>
	/// Clear button for the unsigned files deployment button flyout
	/// </summary>
	internal void BrowseForXMLPolicyFilesButton_Flyout_Clear_Click()
	{
		XMLFiles.Clear();
	}

	/// <summary>
	/// Clear button for the Signed files deployment button flyout
	/// </summary>
	internal void BrowseForSignedXMLPolicyFilesButton_Flyout_Clear_Click()
	{
		SignedXMLFiles.Clear();
	}

	/// <summary>
	/// Event handler for browse button - Signed XML files
	/// </summary>
	internal void BrowseForSignedXMLPolicyFilesButton_Click()
	{

		List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (selectedFiles.Count > 0)
		{
			foreach (string file in selectedFiles)
			{
				SignedXMLFiles.Add(file);
			}
		}
	}

	/// <summary>
	/// Event handler for the button to convert XML files to CIP binary files
	/// </summary>
	internal void BrowseForXMLPolicesButton_Click()
	{
		List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (selectedFiles.Count > 0)
		{
			foreach (string file in selectedFiles)
			{
				XMLFilesToConvertToCIP.Add(file);
			}
		}
	}

	/// <summary>
	/// When online features are enabled, this method will enable the relevant buttons and performs extra necessary actions
	/// </summary>
	/// <param name="on"></param>
	private void UpdateButtonsStates(bool on)
	{
		// Enable the options if a valid value is set as Active Account
		DeployToIntune = on;
		AreOnlineFeaturesEnabled = on;
		LocalOnlineStatusText = on ? GlobalVars.GetStr("CloudDeploymentActive") : GlobalVars.GetStr("LocalDeploymentActive");

		// If online features are turned off, clear the list of Intune groups
		if (!on)
		{
			GroupNamesCollection.Clear();
		}
	}


	/// <summary>
	/// Deploy unsigned XML files button
	/// </summary>
	internal async void DeployUnsignedXMLButton_Click()
	{
		if (XMLFiles.Count is 0)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("SelectUnsignedXMLFilesToDeployWarningMsg"));
			return;
		}

		bool errorsOccurred = false;

		try
		{
			// Disable the UI elements
			AreElementsEnabled = false;

			MainInfoBar.WriteInfo(GlobalVars.GetStr("DeployingXMLFiles") + XMLFiles.Count + GlobalVars.GetStr("UnsignedXMLFiles"));

			MainInfoBarIsClosable = false;

			MainProgressBarVisibility = Visibility.Visible;

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
						throw new InvalidOperationException(GlobalVars.GetStr("SignedPolicyError") + file + "'");
					}

					string randomString = Guid.CreateVersion7().ToString("N");

					string xmlFileName = Path.GetFileName(file);

					string CIPFilePath = Path.Combine(stagingArea.FullName, $"{xmlFileName}-{randomString}.cip");

					await Dispatcher.EnqueueAsync(() =>
					{
						MainInfoBar.WriteInfo(GlobalVars.GetStr("DeployingXMLFile") + file + "'");
					});

					// Convert the XML file to CIP
					Management.ConvertXMLToBinary(file, null, CIPFilePath);

					if (DeployToIntune)
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
		catch (Exception ex)
		{
			errorsOccurred = true;
			MainInfoBar.WriteError(ex, GlobalVars.GetStr("DeploymentError"));
		}
		finally
		{
			if (!errorsOccurred)
			{
				MainInfoBar.WriteSuccess(GlobalVars.GetStr("DeploymentSuccess"));

				// Clear the lists at the end if no errors occurred
				XMLFiles.Clear();
			}

			// Re-enable the UI elements
			AreElementsEnabled = true;

			MainProgressBarVisibility = Visibility.Collapsed;
			MainInfoBarIsClosable = true;
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
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Deployment_IntuneGroupsListView);

		try
		{
			// ID(s) of the groups to assign the policy to
			List<string> groupIDs = [];

			if (lv is not null)
			{
				await Dispatcher.EnqueueAsync(() =>
				{
					foreach (var item in lv.SelectedItems)
					{
						// Get the group name
						IntuneGroupItemListView _item = (IntuneGroupItemListView)item;

						groupIDs.Add(_item.GroupID);
					}
				});
			}

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

					policyName = PolicySettingsManager.GetPolicyName(policyObj, null);

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
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}


	/// <summary>
	/// Deploy Signed XML files button
	/// </summary>
	internal async void DeploySignedXMLButton_Click()
	{

		if (SignedXMLFiles.Count is 0)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("SelectXMLFilesToSignAndDeployWarningMsg"));
			return;
		}

		#region Signing Details acquisition

		string CertCN;
		string CertPath;
		string SignToolPath;

		// Instantiate the Content Dialog
		using SigningDetailsDialog customDialog = new();

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
			// Disable the UI elements
			AreElementsEnabled = false;

			MainInfoBarIsClosable = false;

			MainInfoBar.WriteInfo(GlobalVars.GetStr("DeployingXMLFiles") + SignedXMLFiles.Count + GlobalVars.GetStr("SignedXMLFiles"));

			MainProgressBarVisibility = Visibility.Visible;

			// Deploy the selected files
			await Task.Run(async () =>
			{

				DirectoryInfo stagingArea = StagingArea.NewStagingArea("SignedDeployments");

				// Convert and then deploy each XML file
				foreach (string file in SignedXMLFiles)
				{

					await Dispatcher.EnqueueAsync(() =>
					{
						MainInfoBar.WriteInfo((SignOnlyNoDeployToggleSwitch ? GlobalVars.GetStr("CurrentlySigningXMLFile") : GlobalVars.GetStr("DeployingXMLFile")) + file + "'");
					});

					// Add certificate's details to the policy
					SiPolicy.SiPolicy policyObject = AddSigningDetails.Add(file, CertPath);

					// Define the path for the CIP file
					string randomString = Guid.CreateVersion7().ToString("N");
					string xmlFileName = Path.GetFileName(file);
					string CIPFilePath = Path.Combine(stagingArea.FullName, $"{xmlFileName}-{randomString}.cip");

					string CIPp7SignedFilePath = Path.Combine(stagingArea.FullName, $"{xmlFileName}-{randomString}.cip.p7");

					// Convert the XML file to CIP, overwriting the unsigned one
					Management.ConvertXMLToBinary(file, null, CIPFilePath);

					// Sign the CIP
					SignToolHelper.Sign(new FileInfo(CIPFilePath), new FileInfo(SignToolPath), CertCN);

					// Rename the .p7 signed file to .cip
					File.Move(CIPp7SignedFilePath, CIPFilePath, true);

					// If the SignOnlyNoDeployToggleSwitch is on, don't deploy the policy, only create signed CIP
					if (SignOnlyNoDeployToggleSwitch)
					{
						File.Move(CIPFilePath, Path.Combine(GlobalVars.UserConfigDir, $"{Path.GetFileNameWithoutExtension(file)}.CIP"), true);
					}
					else
					{
						if (DeployToIntune)
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
								Logger.Write(GlobalVars.GetStr("PolicyConflictMessage") + possibleAlreadyDeployedUnsignedVersion.PolicyID + GlobalVars.GetStr("RemovingPolicy"));

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
		catch (Exception ex)
		{
			errorsOccurred = true;
			MainInfoBar.WriteError(ex, GlobalVars.GetStr("DeploymentError"));
		}
		finally
		{
			if (!errorsOccurred)
			{
				MainInfoBar.WriteSuccess(SignOnlyNoDeployToggleSwitch ? GlobalVars.GetStr("SuccessfullyCreatedSignedCIPFiles") : GlobalVars.GetStr("SignedDeploymentSuccess"));

				// Clear the lists at the end if no errors occurred
				SignedXMLFiles.Clear();
			}

			// Re-enable the UI elements
			AreElementsEnabled = true;

			MainProgressBarVisibility = Visibility.Collapsed;
			MainInfoBarIsClosable = true;
		}
	}


	/// <summary>
	/// Deploy CIP files button
	/// </summary>
	internal async void DeployCIPButton_Click()
	{
		if (CIPFiles.Count is 0)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("SelectCIPFilesToDeployWarningMsg"));
			return;
		}

		bool errorsOccurred = false;

		try
		{
			AreElementsEnabled = false;
			MainInfoBarIsClosable = false;

			MainInfoBar.WriteInfo(GlobalVars.GetStr("DeployingXMLFiles") + CIPFiles.Count + GlobalVars.GetStr("CIPFiles"));

			MainProgressBarVisibility = Visibility.Visible;

			// Deploy the selected CIP files
			await Task.Run(async () =>
			{
				foreach (string file in CIPFiles)
				{
					await Dispatcher.EnqueueAsync(() =>
					{
						MainInfoBar.WriteInfo(GlobalVars.GetStr("DeployingCIPFile") + file + "'");
					});

					string randomPolicyID = Guid.CreateVersion7().ToString().ToUpperInvariant();

					if (DeployToIntune)
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
		catch (Exception ex)
		{
			errorsOccurred = true;
			MainInfoBar.WriteError(ex, GlobalVars.GetStr("DeploymentError"));
		}
		finally
		{
			if (!errorsOccurred)
			{
				MainInfoBar.WriteSuccess(GlobalVars.GetStr("CIPDeploymentSuccess"));

				// Clear the list at the end if no errors occurred
				CIPFiles.Clear();
			}

			AreElementsEnabled = true;

			MainProgressBarVisibility = Visibility.Collapsed;
			MainInfoBarIsClosable = true;
		}
	}


	/// <summary>
	/// Handles the click event for the Refresh Intune Groups button. It fetches groups from Microsoft Graph and updates
	/// the ListView with group names.
	/// </summary>
	internal async void RefreshIntuneGroupsButton_Click()
	{
		try
		{
			AreOnlineFeaturesEnabled = false;

			Dictionary<string, string> groups = await MicrosoftGraph.Main.FetchGroups(AuthCompanionCLS.CurrentActiveAccount);

			GroupNamesCollection.Clear();

			// Update the ListView with group names
			foreach (KeyValuePair<string, string> item in groups)
			{
				GroupNamesCollection.Add(new IntuneGroupItemListView(item.Key, item.Value));
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			AreOnlineFeaturesEnabled = true;
		}
	}


	/// <summary>
	/// Handles the click event for converting XML files to CIP format.
	/// </summary>
	internal async void ConvertXMLToCIPButton_Click()
	{
		if (XMLFilesToConvertToCIP.Count is 0)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("SelectXMLFilesToDeployWarningMsg"));
			return;
		}

		bool ErrorsOccurred = false;

		try
		{
			AreElementsEnabled = false;

			MainInfoBarIsClosable = false;
			MainProgressBarVisibility = Visibility.Visible;

			await Task.Run(async () =>
			{
				foreach (string file in XMLFilesToConvertToCIP)
				{

					await Dispatcher.EnqueueAsync(() =>
					{
						MainInfoBar.WriteInfo(string.Format(
							GlobalVars.GetStr("ConvertingFileToCIPMessage"),
							file
						));
					});

					string XMLSavePath = Path.Combine(GlobalVars.UserConfigDir, $"{Path.GetFileNameWithoutExtension(file)}.CIP");

					if (File.Exists(XMLSavePath))
					{
						File.Delete(XMLSavePath);
					}

					// Convert the XML file to CIP
					Management.ConvertXMLToBinary(file, null, XMLSavePath);
				}
			});
		}
		catch (Exception ex)
		{
			ErrorsOccurred = true;
			MainInfoBar.WriteError(ex, GlobalVars.GetStr("ErrorConvertingXMLToCIPMessage"));
		}
		finally
		{
			if (!ErrorsOccurred)
			{
				MainInfoBar.WriteSuccess(GlobalVars.GetStr("SuccessfullyConvertedXMLFilesToCIPMessage"));
			}

			MainInfoBarIsClosable = true;
			MainProgressBarVisibility = Visibility.Collapsed;

			AreElementsEnabled = true;
		}

	}

	public void Dispose()
	{
		try
		{
			// Unsubscribe from the collection changed event to prevent memory leaks
			ViewModelMSGraph.AuthenticatedAccounts.CollectionChanged -= AuthCompanionCLS.AuthenticatedAccounts_CollectionChanged;
		}
		catch { }

		// Dispose the AuthenticationCompanion which implements IDisposable
		AuthCompanionCLS?.Dispose();
	}
}
