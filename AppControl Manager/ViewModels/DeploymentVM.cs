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
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using AppControlManager.CustomUIElements;
using AppControlManager.Others;
using AppControlManager.Pages;
using AppControlManager.SiPolicy;
using AppControlManager.SiPolicyIntel;
using AppControlManager.XMLOps;
using CommonCore.MicrosoftGraph;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.ViewModels;

internal sealed partial class DeploymentVM : ViewModelBase, IGraphAuthHost, IDisposable
{
	internal DeploymentVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

		AuthCompanionCLS = new(UpdateButtonsStates, new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher), AuthenticationContext.Intune);

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

	internal readonly UniquePolicyFileRepresentObservableCollection FilesForUnsignedDeployment = [];
	internal readonly UniquePolicyFileRepresentObservableCollection FilesForSignedDeployment = [];
	internal readonly UniqueStringObservableCollection CIPFiles = [];
	internal readonly UniqueStringObservableCollection XMLFilesToConvertToCIP = [];

	public AuthenticationCompanion AuthCompanionCLS { get; private set; }

	internal bool DeploySignedXMLButtonIsEnabled { get; set => SP(ref field, value); }

	/// <summary>
	/// When true, policies will be deployed to Intune instead of the local system.
	/// </summary>
	internal bool DeployToIntune { get; set => SP(ref field, value); }

	/// <summary>
	/// Determines whether the UI elements are enabled or disabled.
	/// </summary>
	public bool AreElementsEnabled { get; set => SP(ref field, value); } = true;

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
	/// Used to display the number of selected groups in the UI.
	/// </summary>
	internal int SelectedIntuneGroupsCount => IntuneDeploymentDetailsVM.SelectedIntuneGroups.Count;

	/// <summary>
	/// Controls the visibility of the Main progress bar.
	/// </summary>
	internal Visibility MainProgressBarVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	/// <summary>
	/// Event handler to clear the list of XML files that are only converted to CIP files
	/// </summary>
	internal void BrowseForXMLPolicesButton_Flyout_Clear_Click() => XMLFilesToConvertToCIP.Clear();

	/// <summary>
	/// Event handler for browse button - policy files to deploy unsigned.
	/// </summary>
	internal async void BrowseForXMLPolicyFilesButton_Click()
	{
		try
		{
			List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.XMLFilePickerFilter);

			foreach (string file in selectedFiles)
			{
				SiPolicy.SiPolicy policyObj = await Task.Run(() => Management.Initialize(file, null));

				FilesForUnsignedDeployment.Add(new(policyObj));
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Event handler for Browse button - CIP files
	/// </summary>
	internal void BrowseForCIPBinaryFilesButton_Click()
	{
		List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.CIPFilesPickerFilter);

		foreach (string file in CollectionsMarshal.AsSpan(selectedFiles))
		{
			CIPFiles.Add(file);
		}
	}

	/// <summary>
	/// Clear button for the CIP files deployment button flyout
	/// </summary>
	internal void BrowseForCIPBinaryFilesButton_Flyout_Clear_Click() => CIPFiles.Clear();

	/// <summary>
	/// Clear button for the unsigned files deployment button flyout
	/// </summary>
	internal void BrowseForXMLPolicyFilesButton_Flyout_Clear_Click() => FilesForUnsignedDeployment.Clear();

	/// <summary>
	/// Clear button for the Signed files deployment button flyout
	/// </summary>
	internal void BrowseForSignedXMLPolicyFilesButton_Flyout_Clear_Click() => FilesForSignedDeployment.Clear();

	/// <summary>
	/// Event handler for browse button - policy files to deploy signed.
	/// </summary>
	internal async void BrowseForSignedXMLPolicyFilesButton_Click()
	{
		try
		{
			List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.XMLFilePickerFilter);

			foreach (string file in selectedFiles)
			{
				SiPolicy.SiPolicy policyObj = await Task.Run(() => Management.Initialize(file, null));

				FilesForSignedDeployment.Add(new(policyObj) { FilePath = file });
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Event handler for the button to convert XML files to CIP binary files
	/// </summary>
	internal void BrowseForXMLPolicesButton_Click()
	{
		List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		foreach (string file in CollectionsMarshal.AsSpan(selectedFiles))
		{
			XMLFilesToConvertToCIP.Add(file);
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
	}

	/// <summary>
	/// Event handler for the button that deploys the user-selected policy files Unsigned.
	/// </summary>
	internal async void DeployUnsignedXMLButton_Click()
	{
		if (FilesForUnsignedDeployment.Count is 0)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("SelectUnsignedXMLFilesToDeployWarningMsg"));
			return;
		}

		try
		{
			// Disable the UI elements
			AreElementsEnabled = false;

			MainInfoBar.WriteInfo(GlobalVars.GetStr("DeployingXMLFiles") + FilesForUnsignedDeployment.Count + GlobalVars.GetStr("UnsignedXMLFiles"));

			MainInfoBarIsClosable = false;

			MainProgressBarVisibility = Visibility.Visible;

			// Deploy the selected files
			await Task.Run(async () =>
			{
				// Convert and then deploy each XML file
				foreach (PolicyFileRepresent file in FilesForUnsignedDeployment)
				{
					if (!file.PolicyObj.Rules.Any(rule => rule.Item is OptionType.EnabledUnsignedSystemIntegrityPolicy))
					{
						throw new InvalidOperationException(string.Format(GlobalVars.GetStr("SignedPolicyError"), file));
					}

					MainInfoBar.WriteInfo(GlobalVars.GetStr("DeployingXMLFile") + file + "'");

					if (DeployToIntune)
					{
						await DeployToIntunePrivate(file.PolicyObj, Management.ConvertXMLToBinary(file.PolicyObj));
					}
					else
					{
						PreDeploymentChecks.CheckForSignatureConflict(file.PolicyObj);

						// Deploy the CIP locally
						CiToolHelper.UpdatePolicy(Management.ConvertXMLToBinary(file.PolicyObj));

						// Deploy the AppControlManager supplemental policy
						if (SupplementalForSelf.IsEligible(file.PolicyObj))
							SupplementalForSelf.Deploy(file.PolicyObj.PolicyID);
					}
				}
			});

			MainInfoBar.WriteSuccess(GlobalVars.GetStr("DeploymentSuccess"));

			// Clear the lists at the end if no errors occurred
			FilesForUnsignedDeployment.Clear();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, GlobalVars.GetStr("DeploymentError"));
		}
		finally
		{
			// Re-enable the UI elements
			AreElementsEnabled = true;

			MainProgressBarVisibility = Visibility.Collapsed;
			MainInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// Deploys a specified SiPolicy object to Intune.
	/// </summary>
	/// <param name="policyBytes">
	/// This is required for Signed policies because we sign the CIP content and the bytes are needed,
	/// since we cannot sign the SiPolicy object itself. And for consistency also requiring it for Unsigned policies as well.
	/// </param>
	/// <returns>This method does not return a value.</returns>
	private async Task DeployToIntunePrivate(SiPolicy.SiPolicy policyObj, byte[] policyBytes)
	{
		if (AuthCompanionCLS.CurrentActiveAccount is null)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("SignInAuthenticationRequiredMsg"));
			return;
		}

		// Name of the policy that will be uploaded
		string? policyName = null;

		// The description text for the Intune portal
		// It will contain all of the information related to the policy
		string descriptionText = null!;

		await Task.Run(() =>
		{
			policyName = PolicySettingsManager.GetPolicyName(policyObj);

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
		});

		await CommonCore.MicrosoftGraph.Main.UploadPolicyToIntune(AuthCompanionCLS.CurrentActiveAccount, policyBytes, policyObj, IntuneDeploymentDetailsVM.SelectedIntuneGroups.Select(x => x.GroupID).ToList(), policyName, descriptionText);
	}

	/// <summary>
	/// Event handler for the button that deploys the user-selected policy files Signed.
	/// </summary>
	internal async void DeploySignedXMLButton_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
	{
		if (FilesForSignedDeployment.Count is 0)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("SelectXMLFilesToSignAndDeployWarningMsg"));
			return;
		}

		#region Signing Details acquisition

		string CertCN;
		string CertPath;

		// Instantiate the Content Dialog
		using SigningDetailsDialog customDialog = new();

		// Show the dialog and await its result
		ContentDialogResult result = await customDialog.ShowAsync();

		// Ensure primary button was selected
		if (result is ContentDialogResult.Primary)
		{
			CertPath = customDialog.CertificatePath!;
			CertCN = customDialog.CertificateCommonName!;
		}
		else
		{
			return;
		}

		#endregion

		try
		{
			// Disable the UI elements
			AreElementsEnabled = false;
			DeploySignedXMLButtonIsEnabled = false;

			MainInfoBarIsClosable = false;

			MainInfoBar.WriteInfo(GlobalVars.GetStr("DeployingXMLFiles") + FilesForSignedDeployment.Count + GlobalVars.GetStr("SignedXMLFiles"));

			MainProgressBarVisibility = Visibility.Visible;

			// Deploy the selected files
			await Task.Run(async () =>
			{
				// Convert and then deploy each XML file
				foreach (PolicyFileRepresent file in FilesForSignedDeployment)
				{
					MainInfoBar.WriteInfo((SignOnlyNoDeployToggleSwitch ? GlobalVars.GetStr("CurrentlySigningXMLFile") : GlobalVars.GetStr("DeployingXMLFile")) + file + "'");

					// Add certificate's details to the policy
					file.PolicyObj = AddSigningDetails.Add(file.PolicyObj, CertPath);

					if (file.FilePath is not null)
					{
						// Save the XML that has the certificate details back to the file (if file was used)
						// So that when user uses this in other parts of the app, it will be correctly detected as a signed policy.
						Management.SavePolicyToFile(file.PolicyObj, file.FilePath);
					}

					// Assign the signed policy (back) to the Sidebar
					ViewModelProvider.MainWindowVM.AssignToSidebar(file);

					MainWindow.TriggerTransferIconAnimationStatic((UIElement)sender);

					// Convert the policy object to CIP content
					byte[] cipContent = Management.ConvertXMLToBinary(file.PolicyObj);

					// Sign the CIP content
					cipContent = CommonCore.Signing.Main.SignCIP(cipContent, CertCN);

					// If the SignOnlyNoDeployToggleSwitch is on, don't deploy the policy, only create signed CIP
					if (SignOnlyNoDeployToggleSwitch)
					{
						await File.WriteAllBytesAsync(Path.Combine(GlobalVars.UserConfigDir, $"{file.PolicyIdentifier}.CIP"), cipContent);
					}
					else
					{
						if (DeployToIntune)
						{
							await DeployToIntunePrivate(file.PolicyObj, cipContent);
						}
						else
						{
							// Get all of the deployed base and supplemental policies on the system
							List<CiPolicyInfo> policies = CiToolHelper.GetPolicies(false, true, true);

							// Find policies that are Unsigned and have the same PolicyID as the PolicyID of the Signed policy we are deploying so we can remove them.
							CiPolicyInfo? possibleAlreadyDeployedUnsignedVersion = policies.
							FirstOrDefault(x => !x.IsSignedPolicy && string.Equals(file.PolicyObj.PolicyID.Trim('{', '}'), x.PolicyID, StringComparison.OrdinalIgnoreCase));

							if (possibleAlreadyDeployedUnsignedVersion is not null)
							{
								Logger.Write(GlobalVars.GetStr("PolicyConflictMessage") + possibleAlreadyDeployedUnsignedVersion.PolicyID + GlobalVars.GetStr("RemovingPolicy"));

								CiToolHelper.RemovePolicy(possibleAlreadyDeployedUnsignedVersion.PolicyID);
							}

							// Sign and deploy the required AppControlManager supplemental policy
							if (SupplementalForSelf.IsEligible(file.PolicyObj))
								SupplementalForSelf.DeploySigned(file.PolicyObj.PolicyID, CertPath, CertCN);

							// Deploy the CIP file locally
							CiToolHelper.UpdatePolicy(cipContent);
						}
					}
				}
			});

			MainInfoBar.WriteSuccess(SignOnlyNoDeployToggleSwitch ? GlobalVars.GetStr("SuccessfullyCreatedSignedCIPFiles") : GlobalVars.GetStr("SignedDeploymentSuccess"));

			// Clear the lists at the end if no errors occurred
			FilesForSignedDeployment.Clear();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, GlobalVars.GetStr("DeploymentError"));
		}
		finally
		{
			// Re-enable the UI elements
			AreElementsEnabled = true;
			DeploySignedXMLButtonIsEnabled = true;

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
					MainInfoBar.WriteInfo(GlobalVars.GetStr("DeployingCIPFile") + file + "'");

					// Convert the CIP to a SiPolicy object
					SiPolicy.SiPolicy policyObj = BinaryOpsReverse.ConvertBinaryToXmlFile(file);

					if (DeployToIntune)
					{
						await DeployToIntunePrivate(policyObj, Management.ConvertXMLToBinary(policyObj));
					}
					else
					{
						// Deploy the CIP file
						CiToolHelper.UpdatePolicy(Management.ConvertXMLToBinary(policyObj));
					}
				}
			});

			MainInfoBar.WriteSuccess(GlobalVars.GetStr("CIPDeploymentSuccess"));

			// Clear the list at the end if no errors occurred
			CIPFiles.Clear();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, GlobalVars.GetStr("DeploymentError"));
		}
		finally
		{
			AreElementsEnabled = true;

			MainProgressBarVisibility = Visibility.Collapsed;
			MainInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// Event handler for the Select Groups button.
	/// </summary>
	internal void SelectGroups_Click()
	{
		// Assign the current signed in account to the ViewModel to make it available for usage.
		IntuneDeploymentDetailsVM.TargetAccount = AuthCompanionCLS.CurrentActiveAccount;

		ViewModelProvider.NavigationService.Navigate(typeof(IntuneDeploymentDetails), null);
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

		try
		{
			AreElementsEnabled = false;

			MainInfoBarIsClosable = false;
			MainProgressBarVisibility = Visibility.Visible;

			await Task.Run(async () =>
			{
				foreach (string file in XMLFilesToConvertToCIP)
				{
					MainInfoBar.WriteInfo(string.Format(
						GlobalVars.GetStr("ConvertingFileToCIPMessage"),
						file
					));

					string XMLSavePath = Path.Combine(GlobalVars.UserConfigDir, $"{Path.GetFileNameWithoutExtension(file)}.CIP");

					if (File.Exists(XMLSavePath))
					{
						File.Delete(XMLSavePath);
					}

					// Convert the XML file to CIP
					Management.ConvertXMLToBinary(file, XMLSavePath);
				}
			});

			MainInfoBar.WriteSuccess(GlobalVars.GetStr("SuccessfullyConvertedXMLFilesToCIPMessage"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, GlobalVars.GetStr("ErrorConvertingXMLToCIPMessage"));
		}
		finally
		{
			MainInfoBarIsClosable = true;
			MainProgressBarVisibility = Visibility.Collapsed;

			AreElementsEnabled = true;
		}
	}

	public void Dispose()
	{
		// Dispose the AuthenticationCompanion which implements IDisposable
		AuthCompanionCLS.Dispose();
	}
}
