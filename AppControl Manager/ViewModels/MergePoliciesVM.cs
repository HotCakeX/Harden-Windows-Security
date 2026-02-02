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
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.SiPolicy;
using AppControlManager.XMLOps;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.ViewModels;

internal sealed partial class MergePoliciesVM : ViewModelBase
{
	internal MergePoliciesVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => PolicyMergerInfoBarIsOpen, value => PolicyMergerInfoBarIsOpen = value,
			() => PolicyMergerInfoBarMessage, value => PolicyMergerInfoBarMessage = value,
			() => PolicyMergerInfoBarSeverity, value => PolicyMergerInfoBarSeverity = value,
			() => PolicyMergerInfoBarIsClosable, value => PolicyMergerInfoBarIsClosable = value,
			Dispatcher,
			() => PolicyMergerInfoBarTitle, value => PolicyMergerInfoBarTitle = value);

		AdvancedFeaturesInfoBar = new InfoBarSettings(
			() => AdvancedFeaturesInfoBarIsOpen, value => AdvancedFeaturesInfoBarIsOpen = value,
			() => AdvancedFeaturesInfoBarMessage, value => AdvancedFeaturesInfoBarMessage = value,
			() => AdvancedFeaturesInfoBarSeverity, value => AdvancedFeaturesInfoBarSeverity = value,
			() => AdvancedFeaturesInfoBarIsClosable, value => AdvancedFeaturesInfoBarIsClosable = value,
			Dispatcher,
			() => AdvancedFeaturesInfoBarTitle, value => AdvancedFeaturesInfoBarTitle = value);
	}

	private readonly InfoBarSettings MainInfoBar;

	#region UI-Bound Properties

	internal readonly UniquePolicyFileRepresentObservableCollection OtherPolicies = [];

	internal bool ShouldDeploy { get; set => SP(ref field, value); }

	internal PolicyFileRepresent? MainPolicy { get; set => SP(ref field, value); }

	internal bool MergeButtonState { get; set => SP(ref field, value); } = true;

	internal bool PolicyMergerInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? PolicyMergerInfoBarMessage { get; set => SP(ref field, value); }
	internal string? PolicyMergerInfoBarTitle { get; set => SP(ref field, value); }
	internal InfoBarSeverity PolicyMergerInfoBarSeverity { get; set => SP(ref field, value); }
	internal bool PolicyMergerInfoBarIsClosable { get; set => SP(ref field, value); }

	internal Visibility MergeProgressRingVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal Visibility MainMergePolicyLightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility OtherMergePoliciesLightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	#endregion

	/// <summary>
	/// Event handler for the main Merge button
	/// </summary>
	internal async void MergeButton_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
	{

		if (MainPolicy is null)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("MergePolicies_SelectMainPolicySubtitle"));
			return;
		}

		if (OtherPolicies.Count is 0)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("MergePolicies_SelectOtherPoliciesSubtitle"));
			return;
		}

		try
		{
			MergeButtonState = false;
			MergeProgressRingVisibility = Visibility.Visible;

			PolicyMergerInfoBarIsClosable = false;

			MainInfoBar.WriteInfo(GlobalVars.GetStr("MergePolicies_MergingMessage"));

			await Task.Run(() =>
			{
				List<SiPolicy.SiPolicy> otherPolicyObjs = [];

				foreach (PolicyFileRepresent item in OtherPolicies)
				{
					otherPolicyObjs.Add(item.PolicyObj);
				}

				// Perform the merge operation
				MainPolicy.PolicyObj = Merger.Merge(MainPolicy.PolicyObj, otherPolicyObjs);

				// Assign the created policy to the Sidebar
				ViewModelProvider.MainWindowVM.AssignToSidebar(MainPolicy);

				MainWindow.TriggerTransferIconAnimationStatic((UIElement)sender);

				if (MainPolicy.FilePath is not null)
				{
					// Save the merge results to the user selected's main policy path, if provided.
					Management.SavePolicyToFile(MainPolicy.PolicyObj, MainPolicy.FilePath);
				}

				// If user chose to deploy the policy after merge
				if (ShouldDeploy)
				{
					MainInfoBar.WriteInfo(GlobalVars.GetStr("MergePolicies_DeployingMessage"));

					PreDeploymentChecks.CheckForSignatureConflict(MainPolicy.PolicyObj);

					// If a base policy is being deployed, ensure it's supplemental policy for AppControl Manager also gets deployed
					if (SupplementalForSelf.IsEligible(MainPolicy.PolicyObj))
						SupplementalForSelf.Deploy(MainPolicy.PolicyObj.PolicyID);

					CiToolHelper.UpdatePolicy(Management.ConvertXMLToBinary(MainPolicy.PolicyObj));
				}
			});

			MainInfoBar.WriteSuccess(GlobalVars.GetStr("MergePolicies_SuccessMessage"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, GlobalVars.GetStr("MergePolicies_ErrorMessage"));
		}
		finally
		{
			PolicyMergerInfoBarIsClosable = true;
			MergeProgressRingVisibility = Visibility.Collapsed;
			MergeButtonState = true;
		}
	}

	/// <summary>
	/// Handles the click event for the Main Policy Browse button. Opens a file picker dialog to select an XML file and
	/// stores the path.
	/// </summary>
	internal async void MainPolicyBrowseButton_Click()
	{
		try
		{
			string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

			if (!string.IsNullOrEmpty(selectedFile))
			{
				SiPolicy.SiPolicy policyObj = await Task.Run(() => Management.Initialize(selectedFile, null));

				// Saving the file path so that if user browsed for XML file
				// The result can be saved back to the same file.
				MainPolicy = new(policyObj) { FilePath = selectedFile };
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Handles the click event for the Other Policies browse button. It opens a file picker dialog to select multiple XML
	/// files and adds unique selections to a display string.
	/// </summary>
	internal async void OtherPoliciesBrowseButton_Click()
	{
		try
		{
			List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.XMLFilePickerFilter);

			foreach (string item in selectedFiles)
			{
				SiPolicy.SiPolicy policyObj = await Task.Run(() => Management.Initialize(item, null));
				OtherPolicies.Add(new PolicyFileRepresent(policyObj) { FilePath = item });
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Clears the text box for the main selected policy
	/// </summary>
	internal void MainPolicy_Flyout_ClearButton() => MainPolicy = null;

	/// <summary>
	/// Clears the textbox for other selected policies
	/// </summary>
	internal void OtherPolicies_Flyout_ClearButton() => OtherPolicies.Clear();


	#region Advanced Features Section

	private readonly InfoBarSettings AdvancedFeaturesInfoBar;

	internal bool AdvancedFeaturesInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? AdvancedFeaturesInfoBarMessage { get; set => SP(ref field, value); }
	internal string? AdvancedFeaturesInfoBarTitle { get; set => SP(ref field, value); }
	internal InfoBarSeverity AdvancedFeaturesInfoBarSeverity { get; set => SP(ref field, value); }
	internal bool AdvancedFeaturesInfoBarIsClosable { get; set => SP(ref field, value); }

	/// <summary>
	/// Whether the elements for converting policies to AppIDTagging type are enabled or not.
	/// </summary>
	internal bool ConvertToAppIDTaggingElementsAreEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				PoliciesToConvertToAppIDTaggingProgressRingVisibility = field ? Visibility.Collapsed : Visibility.Visible;
			}
		}
	} = true;

	/// <summary>
	/// Collection of policies to convert to AppID Tagging.
	/// </summary>
	internal readonly UniquePolicyFileRepresentObservableCollection PoliciesToConvertToAppIDTagging = [];

	/// <summary>
	/// Event handler to clear the collection of policies to convert to AppID Tagging.
	/// </summary>
	internal void PoliciesToConvertToAppIDTagging_Clear() => PoliciesToConvertToAppIDTagging.Clear();

	internal Visibility PoliciesToConvertToAppIDTaggingProgressRingVisibility
	{
		get; set => SP(ref field, value);
	} = Visibility.Collapsed;

	internal Visibility AppIDTagConversionPolicyLightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	/// <summary>
	/// Event handler to select policies to convert to AppIDTagging type.
	/// </summary>
	internal async void PoliciesToConvertToAppIDTaggingBrowseButton_Click()
	{
		try
		{
			List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.MultiAppControlPolicyPickerFilter);

			foreach (string file in selectedFiles)
			{
				PolicyFileRepresent policy = await Task.Run(() => PolicyEditorVM.ParseFilePathAsPolicyRepresent(file));

				PoliciesToConvertToAppIDTagging.Add(policy);
			}
		}
		catch (Exception ex)
		{
			AdvancedFeaturesInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Event handler for the button to convert the selected policies to AppIDTagging type.
	/// </summary>
	internal async void ConvertToAppIDTagging(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
	{
		try
		{
			if (PoliciesToConvertToAppIDTagging.Count == 0)
				return;

			ConvertToAppIDTaggingElementsAreEnabled = false;
			AdvancedFeaturesInfoBar.IsClosable = false;

			await Task.Run(() =>
			{
				foreach (PolicyFileRepresent policy in PoliciesToConvertToAppIDTagging)
				{
					policy.PolicyObj = AppIDTagging.Convert(policy.PolicyObj);

					Dictionary<string, string> tags = [];
					tags["AppIDTaggingKey"] = "True";

					policy.PolicyObj = AppIDTagging.AddTags(policy.PolicyObj, tags);

					policy.PolicyObj = Merger.Merge(policy.PolicyObj, null);

					// Assign the created policy to the Sidebar
					ViewModelProvider.MainWindowVM.AssignToSidebar(policy);

					MainWindow.TriggerTransferIconAnimationStatic((UIElement)sender);

					if (policy.FilePath is not null)
					{
						Management.SavePolicyToFile(policy.PolicyObj, policy.FilePath);
					}
				}
			});

			AdvancedFeaturesInfoBar.WriteSuccess(GlobalVars.GetStr("SuccessMsgConvertingPoliciesToAppIDTagging"));
		}
		catch (Exception ex)
		{
			AdvancedFeaturesInfoBar.WriteError(ex);
		}
		finally
		{
			ConvertToAppIDTaggingElementsAreEnabled = true;
			AdvancedFeaturesInfoBar.IsClosable = true;
		}
	}


	// Signing Scenario Removal Section

	internal Visibility SigningScenarioRemovalPolicyLightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool UserModeSigningScenarioSelected { get; set => SP(ref field, value); }
	internal bool KernelModeSigningScenarioSelected { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Whether the elements for removing Signing Scenarios are enabled or not.
	/// </summary>
	internal bool SigningScenarioRemovalElementsAreEnabled { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Collection of policies to convert to AppID Tagging.
	/// </summary>
	internal readonly UniquePolicyFileRepresentObservableCollection PoliciesForSigningScenarioRemoval = [];

	/// <summary>
	/// Event handler to clear the collection of policies to convert to AppID Tagging.
	/// </summary>
	internal void PoliciesForSigningScenarioRemoval_Clear() => PoliciesForSigningScenarioRemoval.Clear();

	/// <summary>
	/// Event handler to select policies to for Signing Scenario removal.
	/// </summary>
	internal async void PoliciesForSigningScenarioRemovalBrowseButton_Click()
	{
		try
		{
			List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.MultiAppControlPolicyPickerFilter);

			foreach (string file in selectedFiles)
			{
				PolicyFileRepresent policy = await Task.Run(() => PolicyEditorVM.ParseFilePathAsPolicyRepresent(file));

				PoliciesForSigningScenarioRemoval.Add(policy);
			}
		}
		catch (Exception ex)
		{
			AdvancedFeaturesInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Event handler for the button that removes Signing Scenario from policies.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal async void RemoveSigningScenario(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
	{
		try
		{
			if (PoliciesForSigningScenarioRemoval.Count == 0)
				return;

			SigningScenarioRemovalElementsAreEnabled = false;
			AdvancedFeaturesInfoBar.IsClosable = false;

			await Task.Run(() =>
			{
				if (UserModeSigningScenarioSelected)
				{
					foreach (PolicyFileRepresent policy in PoliciesForSigningScenarioRemoval)
					{
						policy.PolicyObj = RemoveSigningScenarios.RemoveUserMode(policy.PolicyObj);

						// Assign the created policy to the Sidebar
						ViewModelProvider.MainWindowVM.AssignToSidebar(policy);

						MainWindow.TriggerTransferIconAnimationStatic((UIElement)sender);

						if (policy.FilePath is not null)
						{
							Management.SavePolicyToFile(policy.PolicyObj, policy.FilePath);
						}
					}
				}
				else if (KernelModeSigningScenarioSelected)
				{
					foreach (PolicyFileRepresent policy in PoliciesForSigningScenarioRemoval)
					{
						policy.PolicyObj = RemoveSigningScenarios.RemoveKernelMode(policy.PolicyObj);

						// Assign the created policy to the Sidebar
						ViewModelProvider.MainWindowVM.AssignToSidebar(policy);

						MainWindow.TriggerTransferIconAnimationStatic((UIElement)sender);

						if (policy.FilePath is not null)
						{
							Management.SavePolicyToFile(policy.PolicyObj, policy.FilePath);
						}
					}
				}
			});

			AdvancedFeaturesInfoBar.WriteSuccess(GlobalVars.GetStr("SuccessMsgSigningScenarioRemoval"));
		}
		catch (Exception ex)
		{
			AdvancedFeaturesInfoBar.WriteError(ex);
		}
		finally
		{
			SigningScenarioRemovalElementsAreEnabled = true;
			AdvancedFeaturesInfoBar.IsClosable = true;
		}
	}


	#endregion


}
